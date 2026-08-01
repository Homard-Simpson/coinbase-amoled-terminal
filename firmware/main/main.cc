#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "sdkconfig.h"
#include "cJSON.h"
#include "driver/gpio.h"
#include "driver/i2c_master.h"
#include "driver/spi_master.h"
#include "esp_crt_bundle.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"

#if CONFIG_TERMINAL_BOARD_V1
#define BOARD_IS_V1 1
#else
#define BOARD_IS_V1 0
#endif

#if BOARD_IS_V1
#include "esp_lcd_sh8601.h"
#include "esp_lcd_touch_ft5x06.h"
#else
#include "esp_lcd_co5300.h"
#include "esp_lcd_touch_cst816s.h"
#endif
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_touch.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_io_expander.h"
#include "esp_io_expander_tca9554.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "network_portal.h"
#include "onboarding_metadata.h"
#include "runtime_config.h"

#define PROGMEM
#include "glcdfont.h"

static const char *TAG = "amoled-terminal";
static constexpr int W=368,H=448,TX_LINES=16;
#if BOARD_IS_V1
static constexpr int PANEL_X_GAP=0;
#else
static constexpr int PANEL_X_GAP=0x10;
#endif
static constexpr int BOOT_SPLASH_MS=750;
static constexpr int HISTORY_SAMPLES=60;
static constexpr int CANDLE_SAMPLES=36;
static constexpr size_t MAX_FEED_BYTES=192*1024;
static constexpr uint32_t REFRESH_MS=30000, MIN_STALE_MS=75000;
static esp_lcd_panel_handle_t panel;
static esp_lcd_panel_io_handle_t lcd_io;
static esp_lcd_touch_handle_t touch;
static uint16_t *fb, *txbuf;
static SemaphoreHandle_t tx_done;
static i2c_master_bus_handle_t i2c_bus;
static esp_io_expander_handle_t io_expander;
static std::atomic_bool wifi_up{false},force_fetch{true};
static bool detail=false;
static int selected_chart=-1;
static uint32_t feed_refresh_seconds=30,history_sample_seconds=30,candle_interval_seconds=0;
static uint64_t last_ok_ms=0;
static int px_row_y[5],px_row_h[5],px_row_asset[5],px_row_n=0;
// Feed state is produced by a dedicated network task and consumed by the UI loop.
// Heavy shared state is guarded by state_mux; status and event latches are atomic.
enum { ST_STARTING=0, ST_UPDATED, ST_NOWIFI, ST_UNCONFIGURED, ST_HTTPERR,
       ST_JSONERR, ST_TOO_LARGE, ST_UNSAFE };
static std::atomic_int feed_status{ST_STARTING},feed_http_code{0};
static std::atomic_bool data_dirty{true};
static SemaphoreHandle_t state_mux=nullptr;
static std::atomic_int tap_x{-1},tap_y{-1};
static bool screen_on=true;                // BOOT long-press display toggle; no auto-timeout
struct Position { bool open=false; std::string side="-"; double size=0,entry=0,pnl=0; };
struct ClosedPosition { std::string symbol="-",side="-"; double size=0,pnl=0; };
struct Candle { int64_t timestamp=0; double open=0,high=0,low=0,close=0,volume=0; };
struct Asset {
  const char *name; double price=0; Position pos;
  double history[HISTORY_SAMPLES]={}; uint8_t history_count=0,history_head=0;
  Candle candles[CANDLE_SAMPLES]={}; uint8_t candle_count=0;
  explicit Asset(const char*n):name(n){}
};
static Asset assets[]={Asset("BTC"),Asset("SOL"),Asset("XLM"),Asset("HYPE"),Asset("ETH")};
static std::vector<ClosedPosition> closed_today;
static double position_value=0, total_pnl=0, realized_pnl_today=0;
// AXP2101 PMU battery/power state. Read-only over i2c (address 0x34); never write on
// V2 — PMU writes blank the CO5300 panel. Register semantics match the proven
// AXP2101 register semantics: level=0xA4, charge direction=0x01[6:5], done=0x01[2:0]==4.
struct Battery { bool present=false; int level=0; bool charging=false, done=false, vbus=false; };
static Battery g_batt;
static i2c_master_dev_handle_t axp_read_dev=nullptr;

static uint16_t rgb(uint8_t r,uint8_t g,uint8_t b){ return __builtin_bswap16(((r&0xF8)<<8)|((g&0xFC)<<3)|(b>>3)); }
static const uint16_t BLACK=rgb(5,8,15),CARD=rgb(18,24,38),GRID=rgb(45,57,78),MUTED=rgb(190,198,214),WHITE=rgb(245,247,250),GREEN=rgb(48,209,88),RED=rgb(255,69,58),BLUE=rgb(55,126,255),AMBER=rgb(255,180,0);
static void rect(int x,int y,int w,int h,uint16_t c){ x=std::max(0,x); y=std::max(0,y); w=std::min(w,W-x); h=std::min(h,H-y); for(int yy=y;yy<y+h;yy++) std::fill(fb+yy*W+x,fb+yy*W+x+w,c); }
static int text_width(const char*s,int scale=2){ scale=std::max(2,scale); return (int)strlen(s)*6*scale; }
static void text(int x,int y,const char*s,uint16_t c,int scale=2){ scale=std::max(2,scale); for(;*s;s++,x+=6*scale){ unsigned ch=(unsigned char)*s; if(ch<32||ch>127) ch='?'; for(int i=0;i<5;i++){ uint8_t col=font[ch*5+i]; for(int j=0;j<8;j++) if(col&(1<<j)) rect(x+i*scale,y+j*scale,scale,scale,c); } } }
static void text_right(int right,int y,const char*s,uint16_t c,int scale=2){ text(std::max(0,right-text_width(s,scale)),y,s,c,scale); }
static void text_center(int left,int width,int y,const char*s,uint16_t c,int scale=2){ text(left+std::max(0,(width-text_width(s,scale))/2),y,s,c,scale); }
static void text_bold(int x,int y,const char*s,uint16_t c,int scale=2){ text(x,y,s,c,scale); text(x+1,y,s,c,scale); }
static void to_upper(char*s){ for(;*s;s++) if(*s>='a'&&*s<='z') *s=(char)(*s-'a'+'A'); }
static void fmt_money(char *b,size_t n,double v){ double a=fabs(v); if(a>=10000) snprintf(b,n,"$%.0f",v); else if(a>=100) snprintf(b,n,"$%.2f",v); else if(a>=1) snprintf(b,n,"$%.3f",v); else snprintf(b,n,"$%.5f",v); }
static void pixel(int x,int y,uint16_t c){ if(x>=0&&x<W&&y>=0&&y<H)fb[y*W+x]=c; }
static void draw_line(int x0,int y0,int x1,int y1,uint16_t c,int thickness=1){
  int dx=abs(x1-x0),sx=x0<x1?1:-1,dy=-abs(y1-y0),sy=y0<y1?1:-1,err=dx+dy;
  while(true){ for(int yy=0;yy<thickness;yy++)pixel(x0,y0+yy,c); if(x0==x1&&y0==y1)break; int e2=2*err; if(e2>=dy){err+=dy;x0+=sx;} if(e2<=dx){err+=dx;y0+=sy;} }
}
static double num(cJSON*o,const char*k){cJSON*x=cJSON_GetObjectItemCaseSensitive(o,k);double v=cJSON_IsNumber(x)?x->valuedouble:0;return std::isfinite(v)&&fabs(v)<=1e15?v:0;}
static double history_at(const Asset&a,int i){ int start=(a.history_head+HISTORY_SAMPLES-a.history_count)%HISTORY_SAMPLES; return a.history[(start+i)%HISTORY_SAMPLES]; }
static void push_price(Asset&a,double value){ if(!(value>0)||!std::isfinite(value))return; a.history[a.history_head]=value; a.history_head=(a.history_head+1)%HISTORY_SAMPLES; if(a.history_count<HISTORY_SAMPLES)a.history_count++; }
static bool load_price_history(Asset&a,cJSON*root){
  if(!cJSON_IsObject(root))return false;
  cJSON*series=cJSON_GetObjectItemCaseSensitive(root,a.name);
  if(!cJSON_IsArray(series)||cJSON_GetArraySize(series)==0)return false;
  a.history_count=0;a.history_head=0;
  cJSON*item=nullptr;cJSON_ArrayForEach(item,series)if(cJSON_IsNumber(item))push_price(a,item->valuedouble);
  return a.history_count>0;
}
static bool history_bounds(const Asset&a,double&lo,double&hi){
  if(!a.history_count)return false;
  lo=hi=history_at(a,0);
  for(int i=1;i<a.history_count;i++){ double v=history_at(a,i); lo=std::min(lo,v); hi=std::max(hi,v); }
  return true;
}
static double history_change_pct(const Asset&a){ if(a.history_count<2)return 0; double first=history_at(a,0),last=history_at(a,a.history_count-1); return first?((last-first)/first)*100.0:0; }
static double chart_change_pct(const Asset&a){
  if(a.candle_count){ double first=a.candles[0].open,last=a.candles[a.candle_count-1].close; return first?((last-first)/first)*100.0:0; }
  return history_change_pct(a);
}
static double candle_value(cJSON*item,const char*name,const char*short_name,const char*alternate=nullptr){
  cJSON*x=cJSON_GetObjectItemCaseSensitive(item,name);
  if(!cJSON_IsNumber(x)&&short_name)x=cJSON_GetObjectItemCaseSensitive(item,short_name);
  if(!cJSON_IsNumber(x)&&alternate)x=cJSON_GetObjectItemCaseSensitive(item,alternate);
  return cJSON_IsNumber(x)?x->valuedouble:NAN;
}
// Feed candle arrays are compact [timestamp,open,high,low,close,volume]. Object
// form accepts the long field names; short aliases keep the parser tolerant of
// size-optimized feeds. Timestamps may be epoch seconds or epoch milliseconds.
static bool parse_candle(cJSON*item,Candle&out){
  double ts=NAN,o=NAN,h=NAN,l=NAN,c=NAN,v=NAN;
  if(cJSON_IsArray(item)&&cJSON_GetArraySize(item)>=6){
    cJSON*values[6]; for(int i=0;i<6;i++)values[i]=cJSON_GetArrayItem(item,i);
    if(cJSON_IsNumber(values[0]))ts=values[0]->valuedouble;
    if(cJSON_IsNumber(values[1]))o=values[1]->valuedouble;
    if(cJSON_IsNumber(values[2]))h=values[2]->valuedouble;
    if(cJSON_IsNumber(values[3]))l=values[3]->valuedouble;
    if(cJSON_IsNumber(values[4]))c=values[4]->valuedouble;
    if(cJSON_IsNumber(values[5]))v=values[5]->valuedouble;
  } else if(cJSON_IsObject(item)){
    ts=candle_value(item,"timestamp","t","start"); o=candle_value(item,"open","o");
    h=candle_value(item,"high","h"); l=candle_value(item,"low","l");
    c=candle_value(item,"close","c"); v=candle_value(item,"volume","v");
  }
  if(!std::isfinite(ts)||!std::isfinite(o)||!std::isfinite(h)||!std::isfinite(l)||!std::isfinite(c)||!std::isfinite(v)||
     ts<=0||o<=0||h<=0||l<=0||c<=0||v<0||o>1e15||h>1e15||l>1e15||c>1e15||v>1e30||
     h<std::max(o,c)||l>std::min(o,c)||l>h)return false;
  if(ts>100000000000.0)ts/=1000.0; // normalize common epoch-millisecond input
  if(ts>32503680000.0)return false; // bound conversion and chart sorting (year 3000)
  out={static_cast<int64_t>(llround(ts)),o,h,l,c,v};
  return out.timestamp>0;
}
// Keep only the newest 36 valid candles, sorted oldest -> newest. This bounds
// persistent RAM even if a feed accidentally sends a much larger series.
static bool load_candles(Asset&a,cJSON*root){
  a.candle_count=0;
  if(!cJSON_IsObject(root))return false;
  cJSON*series=cJSON_GetObjectItemCaseSensitive(root,a.name);
  if(!cJSON_IsArray(series))return false;
  cJSON*item=nullptr;
  cJSON_ArrayForEach(item,series){
    Candle next; if(!parse_candle(item,next))continue;
    int count=a.candle_count,pos=0;
    while(pos<count&&a.candles[pos].timestamp<next.timestamp)pos++;
    if(pos<count&&a.candles[pos].timestamp==next.timestamp){a.candles[pos]=next;continue;}
    if(count==CANDLE_SAMPLES){
      if(next.timestamp<=a.candles[0].timestamp)continue;
      for(int i=1;i<count;i++)a.candles[i-1]=a.candles[i];
      count--; pos=0; while(pos<count&&a.candles[pos].timestamp<next.timestamp)pos++;
    }
    for(int i=count;i>pos;i--)a.candles[i]=a.candles[i-1];
    a.candles[pos]=next; a.candle_count=static_cast<uint8_t>(count+1);
  }
  return a.candle_count>0;
}
static bool candle_bounds(const Asset&a,double&lo,double&hi,double&max_volume){
  if(!a.candle_count)return false;
  lo=a.candles[0].low; hi=a.candles[0].high; max_volume=0;
  for(int i=0;i<a.candle_count;i++){ lo=std::min(lo,a.candles[i].low); hi=std::max(hi,a.candles[i].high); max_volume=std::max(max_volume,a.candles[i].volume); }
  return true;
}
static void compact_duration(char*b,size_t n,uint64_t seconds){
  if(seconds>=86400&&seconds%86400==0)snprintf(b,n,"%lluD",(unsigned long long)(seconds/86400));
  else if(seconds>=3600&&seconds%3600==0)snprintf(b,n,"%lluH",(unsigned long long)(seconds/3600));
  else if(seconds>=60&&seconds%60==0)snprintf(b,n,"%lluM",(unsigned long long)(seconds/60));
  else snprintf(b,n,"%lluS",(unsigned long long)seconds);
}
static void candle_window(char*b,size_t n,const Asset&a){
  if(!candle_interval_seconds){snprintf(b,n,"%u CANDLES",(unsigned)a.candle_count);return;}
  char interval[16],window[16]; compact_duration(interval,sizeof(interval),candle_interval_seconds);
  compact_duration(window,sizeof(window),(uint64_t)candle_interval_seconds*a.candle_count);
  snprintf(b,n,"%s x %u / %s WINDOW",interval,(unsigned)a.candle_count,window);
}
static void sparkline(const Asset&a,int x,int y,int w,int h,bool full=false){
  if(full){ for(int i=1;i<4;i++)draw_line(x,y+(h*i)/4,x+w-1,y+(h*i)/4,GRID); }
  else draw_line(x,y+h/2,x+w-1,y+h/2,GRID);
  if(!a.history_count)return;
  double lo,hi; history_bounds(a,lo,hi); if(fabs(hi-lo)<1e-12){ double pad=std::max(fabs(hi)*0.0005,0.000001);lo-=pad;hi+=pad; }
  auto px=[&](int i){ return a.history_count<2?x+w/2:x+(i*(w-1))/(a.history_count-1); };
  auto py=[&](double v){ double n=(v-lo)/(hi-lo); n=std::max(0.0,std::min(1.0,n)); return y+h-1-(int)lround(n*(h-1)); };
  uint16_t color=a.history_count<2||history_at(a,a.history_count-1)>=history_at(a,0)?GREEN:RED;
  if(a.history_count==1){ rect(px(0)-2,py(history_at(a,0))-2,5,5,color);return; }
  for(int i=1;i<a.history_count;i++)draw_line(px(i-1),py(history_at(a,i-1)),px(i),py(history_at(a,i)),color,2);
}
static void history_window(char*b,size_t n,const Asset&a){
  uint32_t seconds=a.history_count>1?(a.history_count-1)*history_sample_seconds:0;
  if(seconds>=3600)snprintf(b,n,"%luH %02luM WINDOW",(unsigned long)(seconds/3600),(unsigned long)((seconds%3600)/60));
  else if(seconds>=60)snprintf(b,n,"%luM WINDOW",(unsigned long)(seconds/60));
  else snprintf(b,n,"%luS WINDOW",(unsigned long)seconds);
}
static void flush_frame(){ for(int y=0;y<H;y+=TX_LINES){ int rows=std::min(TX_LINES,H-y); memcpy(txbuf,fb+y*W,W*rows*sizeof(uint16_t)); ESP_ERROR_CHECK(esp_lcd_panel_draw_bitmap(panel,0,y,W,y+rows,txbuf)); if(xSemaphoreTake(tx_done,pdMS_TO_TICKS(2000))!=pdTRUE){ESP_LOGE(TAG,"LCD transfer timeout y=%d",y);break;} } }
static uint8_t axp_read(uint8_t reg){ if(!axp_read_dev)return 0xFF; uint8_t v=0; return i2c_master_transmit_receive(axp_read_dev,&reg,1,&v,1,100)==ESP_OK?v:0xFF; }
static void update_battery(){
  if(!i2c_bus)return;
  if(!axp_read_dev){i2c_device_config_t c={};c.dev_addr_length=I2C_ADDR_BIT_LEN_7;c.device_address=0x34;c.scl_speed_hz=400000;if(i2c_master_bus_add_device(i2c_bus,&c,&axp_read_dev)!=ESP_OK){axp_read_dev=nullptr;return;}}
  uint8_t s1=axp_read(0x00),s2=axp_read(0x01),lvl=axp_read(0xA4);
  if(s1==0xFF&&s2==0xFF&&lvl==0xFF){g_batt=Battery{};return;}
  int dir=(s2&0b01100000)>>5;               // 0 standby, 1 charging, 2 discharging
  g_batt.vbus=(s1&0x20)!=0;                  // STATUS1 bit5 = VBUS good
  g_batt.charging=(dir==1);
  g_batt.done=((s2&0b00000111)==0b00000100); // charge state = done
  g_batt.present=(dir==1||dir==2)||(lvl>=1&&lvl<=100);
  g_batt.level=std::max(0,std::min(100,(int)lvl));
}
// Toggle the AMOLED display for battery saving (display off command, not sleep — wakes
// instantly). Driven only by a physical BOOT long-press; there is no auto-timeout.
static void set_screen(bool on){
  if(on==screen_on)return;
  screen_on=on;
  if(panel) esp_lcd_panel_disp_on_off(panel,on);
  ESP_LOGI(TAG,"screen %s",on?"ON":"OFF");
}
// Battery/power indicator that replaces the old "COINBASE" corner label.
static void draw_battery(int x,int y){
  int bw=40,bh=20,pct=g_batt.level;
  uint16_t lvlcol=!g_batt.present?MUTED:(pct>=50?GREEN:pct>=20?AMBER:RED);
  uint16_t bord=g_batt.charging?BLUE:lvlcol;
  rect(x,y,bw,bh,bord); rect(x+2,y+2,bw-4,bh-4,BLACK);   // hollow body
  rect(x+bw,y+bh/2-4,4,8,bord);                          // terminal nub
  if(g_batt.present){ int fw=(bw-6)*pct/100; if(fw<0)fw=0; if(fw>bw-6)fw=bw-6; rect(x+3,y+3,fw,bh-6,lvlcol); }
  if(g_batt.charging){ int cx=x+bw/2; draw_line(cx+4,y+3,cx-3,y+bh/2,WHITE,2); draw_line(cx-3,y+bh/2,cx+3,y+bh/2,WHITE,2); draw_line(cx+3,y+bh/2,cx-4,y+bh-3,WHITE,2); }
  char lb[16];
  if(g_batt.present)snprintf(lb,sizeof(lb),"%d%%",pct);
  else if(g_batt.vbus)snprintf(lb,sizeof(lb),"USB");
  else snprintf(lb,sizeof(lb),"--");
  text(x+bw+10,y+2,lb,g_batt.charging?BLUE:(g_batt.present?WHITE:MUTED),2);
}
static void draw(){
  rect(0,0,W,H,BLACK); char b[64];
  auto& network=NetworkPortal::GetInstance();
  if(network.IsPortalActive()){
    const RuntimeConfigSnapshot runtime=RuntimeConfig::GetInstance().Snapshot();
    const std::string ssid=network.GetApSsid(),password=network.GetApPassword();
    const std::string id_tail=runtime.device_id.size()>12?runtime.device_id.substr(runtime.device_id.size()-12):runtime.device_id;
    text(20,16,runtime.IsProvisioned()?"SETUP / OTA":"FIRST-BOOT SETUP",WHITE,3);
    text(20,58,"WI-FI",MUTED,2); text(20,82,ssid.c_str(),BLUE,2);
    text(20,118,"PASSWORD",MUTED,2); text(20,142,password.c_str(),WHITE,2);
    text(20,178,"OPEN",MUTED,2); text(20,202,"http://192.168.4.1",WHITE,2);
    snprintf(b,sizeof(b),"ID ...%s",id_tail.c_str()); text(20,242,b,MUTED,2);
    if(network.IsOtaArmed()){
      text(20,286,"OTA ARMED - 5 MIN",AMBER,2);
      const std::string code=network.GetOtaCode();
      snprintf(b,sizeof(b),"CODE %s",code.c_str()); text(20,316,b,WHITE,3);
    } else {
      text(20,286,"OTA LOCKED",GREEN,2);
      text(20,316,"HOLD BOOT 10S TO ARM",MUTED,2);
    }
    text(20,410,"PROTECTED LOCAL AP",MUTED,2);
    flush_frame();
    return;
  }
  const uint64_t now=esp_timer_get_time()/1000;
  const uint64_t stale_after=std::max<uint64_t>(MIN_STALE_MS,(uint64_t)feed_refresh_seconds*2500ULL);
  const bool stale=last_ok_ms&&now-last_ok_ms>stale_after;
  draw_battery(16,12);
  const int status=feed_status.load();
  const bool feed_problem=status!=ST_UPDATED&&status!=ST_STARTING;
  const char*page=selected_chart>=0?assets[selected_chart].name:(detail?"POSITIONS":"PRICES");
  text_right(352,28,page,MUTED,2);
  if(stale||!wifi_up.load()||feed_problem){
    if(stale)snprintf(b,sizeof(b),"STALE");
    else if(!wifi_up.load())snprintf(b,sizeof(b),"OFFLINE");
    else if(status==ST_UNCONFIGURED)snprintf(b,sizeof(b),"SETUP");
    else if(status==ST_HTTPERR)snprintf(b,sizeof(b),"HTTP %d",feed_http_code.load());
    else if(status==ST_JSONERR)snprintf(b,sizeof(b),"JSON ERR");
    else if(status==ST_TOO_LARGE)snprintf(b,sizeof(b),"TOO LARGE");
    else if(status==ST_UNSAFE)snprintf(b,sizeof(b),"UNSAFE");
    else if(status==ST_NOWIFI)snprintf(b,sizeof(b),"NO WIFI");
    else snprintf(b,sizeof(b),"FEED ERR");
    text_right(352,8,b,AMBER,2);
  }
  int top=58;
  if(selected_chart>=0){
    auto&a=assets[selected_chart];
    rect(16,top,336,338,CARD);
    text_bold(28,top+8,a.name,WHITE,3);
    fmt_money(b,sizeof(b),a.price); text(28+(int)strlen(a.name)*18+12,top+14,b,AMBER,2);
    double pct=chart_change_pct(a); snprintf(b,sizeof(b),"%+.2f%%",pct); text_right(340,top+14,b,pct>=0?GREEN:RED,2);
    int gx=32,gy=top+50,gw=304; char t[80];
    if(a.candle_count){
      // Volume candles: body width represents each candle's volume relative to
      // the highest-volume candle in the visible window. No separate volume bars.
      int price_h=224;
      double candle_lo=0,candle_hi=0,max_volume=0; candle_bounds(a,candle_lo,candle_hi,max_volume);
      double lo=candle_lo,hi=candle_hi;
      if(a.price>0&&std::isfinite(a.price)){lo=std::min(lo,a.price);hi=std::max(hi,a.price);}
      if(a.pos.open&&a.pos.entry>0){lo=std::min(lo,a.pos.entry);hi=std::max(hi,a.pos.entry);}
      double range=hi-lo;
      if(range<1e-9){double pad=std::max(fabs(hi)*0.0005,1e-6);lo-=pad;hi+=pad;}
      else {double pad=range*0.04;lo-=pad;hi+=pad;}
      for(int i=0;i<=4;i++){int yy=gy+price_h*i/4;draw_line(gx,yy,gx+gw-1,yy,GRID);}
      auto py=[&](double v){double n=(v-lo)/(hi-lo);n=std::max(0.0,std::min(1.0,n));return gy+price_h-1-(int)lround(n*(price_h-1));};
      int entry_y=-1;
      if(a.pos.open&&a.pos.entry>0){
        entry_y=py(a.pos.entry);
        for(int X=gx;X<gx+gw;X+=10)draw_line(X,entry_y,std::min(X+4,gx+gw-1),entry_y,AMBER);
      }
      int slot=std::max(1,gw/(int)a.candle_count);
      int max_body_w=std::max(1,std::min(11,slot-1));
      if(!(max_body_w&1))max_body_w--;
      for(int i=0;i<a.candle_count;i++){
        const Candle&cd=a.candles[i]; int cx=gx+((2*i+1)*gw)/(2*a.candle_count);
        uint16_t color=cd.close>=cd.open?GREEN:RED;
        int yh=py(cd.high),yl=py(cd.low),yo=py(cd.open),yc=py(cd.close);
        draw_line(cx,yh,cx,yl,color);
        double volume_ratio=max_volume>0?std::max(0.0,std::min(1.0,cd.volume/max_volume)):0.0;
        int body_w=1+(int)lround(volume_ratio*(max_body_w-1));
        if(body_w>1&&!(body_w&1))body_w--;
        int body_top=std::min(yo,yc),body_h=std::max(2,abs(yc-yo)+1);
        rect(cx-body_w/2,body_top,body_w,body_h,color);
      }
      if(entry_y>=0){int label_y=entry_y<gy+17?entry_y+2:entry_y-16;text(gx+2,label_y,"ENTRY",AMBER,2);}
      // Live price is already printed in the header; the dotted blue line and
      // white end marker make its level visible without another crowded label.
      if(a.price>0&&std::isfinite(a.price)){
        int cy=py(a.price); for(int X=gx;X<gx+gw;X+=12)draw_line(X,cy,std::min(X+5,gx+gw-1),cy,BLUE);
        rect(gx+gw-5,cy-2,5,5,WHITE);
      }
      int yb=gy+price_h+8;
      fmt_money(b,sizeof(b),candle_lo);snprintf(t,sizeof(t),"LO %s",b);text(gx,yb,t,MUTED,2);
      fmt_money(b,sizeof(b),candle_hi);snprintf(t,sizeof(t),"HI %s",b);text_right(gx+gw,yb,t,MUTED,2);
      candle_window(b,sizeof(b),a);text(gx,yb+24,b,MUTED,2);text_right(gx+gw,yb+24,"WIDTH=VOL",MUTED,2);
    } else {
      // Legacy/partial feeds retain the former close-only expanded line chart.
      int gh=188; double lo=0,hi=0; bool hb=history_bounds(a,lo,hi);
      if(a.pos.open&&a.pos.entry>0){if(!hb){lo=hi=a.pos.entry;hb=true;}else{lo=std::min(lo,a.pos.entry);hi=std::max(hi,a.pos.entry);}}
      if(!hb){lo=0;hi=1;}
      if(fabs(hi-lo)<1e-9){double pad=std::max(fabs(hi)*0.0005,1e-6);lo-=pad;hi+=pad;}
      for(int i=0;i<=4;i++){int yy=gy+gh*i/4;draw_line(gx,yy,gx+gw-1,yy,GRID);}
      auto py=[&](double v){double n=(v-lo)/(hi-lo);n=std::max(0.0,std::min(1.0,n));return gy+gh-1-(int)lround(n*(gh-1));};
      if(a.pos.open&&a.pos.entry>0){int ey=py(a.pos.entry);for(int X=gx;X<gx+gw;X+=10)draw_line(X,ey,std::min(X+4,gx+gw-1),ey,AMBER);text(gx+2,ey-16,"ENTRY",AMBER,2);}
      if(a.history_count>=2){
        auto px=[&](int i){return gx+(i*(gw-1))/(a.history_count-1);};
        uint16_t col=history_at(a,a.history_count-1)>=history_at(a,0)?GREEN:RED;
        for(int i=1;i<a.history_count;i++)draw_line(px(i-1),py(history_at(a,i-1)),px(i),py(history_at(a,i)),col,2);
        int lxp=px(a.history_count-1),lyp=py(history_at(a,a.history_count-1));rect(lxp-3,lyp-3,6,6,WHITE);
      } else text_center(gx,gw,gy+gh/2-8,"COLLECTING DATA",AMBER,2);
      int yb=gy+gh+8;
      fmt_money(b,sizeof(b),lo);snprintf(t,sizeof(t),"LO %s",b);text(gx,yb,t,MUTED,2);
      fmt_money(b,sizeof(b),hi);snprintf(t,sizeof(t),"HI %s",b);text_right(gx+gw,yb,t,MUTED,2);
      history_window(b,sizeof(b),a);text(gx,yb+24,b,MUTED,2);text_right(gx+gw,yb+24,"TAP < >",MUTED,2);
    }
  } else if(detail){
    // Position-only summary: no cash balance or unrelated account total is requested.
    rect(16,top,336,64,CARD);
    text(28,top+8,"OPEN VALUE",MUTED,2);
    fmt_money(b,sizeof(b),position_value); text(28,top+32,b,WHITE,3);
    snprintf(b,sizeof(b),"UPL %+.2f",total_pnl); text_right(340,top+8,b,total_pnl>=0?GREEN:RED,2);
    snprintf(b,sizeof(b),"RPL %+.2f",realized_pnl_today); text_right(340,top+40,b,realized_pnl_today>=0?GREEN:RED,2);
    int y=top+72;
    int open_total=0; for(auto&a:assets)if(a.pos.open)open_total++;
    snprintf(b,sizeof(b),"OPEN POSITIONS %d",open_total); text(16,y,b,WHITE,2); y+=24;
    if(!open_total){ text(24,y,"NONE",MUTED,2); y+=28; }
    int shown=0;
    for(auto&a:assets){ if(!a.pos.open)continue; if(y+56>392)break;
      uint16_t sc=(a.pos.side.size()&&(a.pos.side[0]=='S'||a.pos.side[0]=='s'))?RED:GREEN;
      rect(16,y,336,56,CARD); rect(16,y,6,56,sc);
      char sd[12]; snprintf(sd,sizeof(sd),"%s",a.pos.side.c_str()); to_upper(sd);
      char nm[28]; snprintf(nm,sizeof(nm),"%s %s",a.name,sd); text(28,y+6,nm,WHITE,2);
      fmt_money(b,sizeof(b),a.price); text_right(350,y+4,b,AMBER,3);            // current price, on top
      char entry[24]; fmt_money(entry,sizeof(entry),a.pos.entry); snprintf(b,sizeof(b),"%.4g @ %s",a.pos.size,entry); text(28,y+34,b,MUTED,2); // size @ purchase price
      snprintf(b,sizeof(b),"U%+.2f",a.pos.pnl); text_right(350,y+34,b,a.pos.pnl>=0?GREEN:RED,2);
      y+=60; shown++;
    }
    if(open_total>shown){ snprintf(b,sizeof(b),"+%d MORE",open_total-shown); text(24,y,b,AMBER,2); y+=24; }
    if(y+40<392){
      snprintf(b,sizeof(b),"CLOSED TODAY %u",(unsigned)closed_today.size()); text(16,y,b,WHITE,2); y+=24;
      if(closed_today.empty())text(24,y,"NONE YET",MUTED,2);
      else{ int cs=0; for(auto&p:closed_today){ if(cs>=2||y+38>392)break; rect(16,y,336,36,CARD); char sd[12]; snprintf(sd,sizeof(sd),"%s",p.side.c_str()); to_upper(sd); snprintf(b,sizeof(b),"%s %s",p.symbol.c_str(),sd); text(24,y+4,b,WHITE,2); snprintf(b,sizeof(b),"R%+.2f",p.pnl); text_right(350,y+4,b,p.pnl>=0?GREEN:RED,2); snprintf(b,sizeof(b),"SIZE %.4g",p.size); text(24,y+20,b,MUTED,2); y+=40; cs++; } }
    }
  } else {
    // PRICES page: open positions get taller/bolder rows with an amber live price.
    int y=top; px_row_n=0;
    for(int i=0;i<5;i++){ auto&a=assets[i]; bool open=a.pos.open; int rh=open?64:50;
      px_row_y[px_row_n]=y; px_row_h[px_row_n]=rh; px_row_asset[px_row_n]=i; px_row_n++;
      rect(16,y,336,rh,CARD);
      if(open){
        uint16_t sc=(a.pos.side.size()&&(a.pos.side[0]=='S'||a.pos.side[0]=='s'))?RED:GREEN;
        rect(16,y,6,rh,sc);
        text_bold(30,y+6,a.name,WHITE,3);
        fmt_money(b,sizeof(b),a.price); text_right(350,y+8,b,AMBER,3);          // live price, distinct color
        char sd[12]; snprintf(sd,sizeof(sd),"%s",a.pos.side.c_str()); to_upper(sd); text(30,y+40,sd,sc,2);
        snprintf(b,sizeof(b),"U%+.2f",a.pos.pnl); text_right(350,y+40,b,a.pos.pnl>=0?GREEN:RED,2);
        sparkline(a,150,y+42,120,16,false);
      } else {
        text(24,y+6,a.name,WHITE,2);
        fmt_money(b,sizeof(b),a.price); text(96,y+6,b,MUTED,2);
        sparkline(a,210,y+4,140,18,false);
        text(24,y+28,"FLAT",MUTED,2);
        double pct=history_change_pct(a); if(a.history_count>=2){snprintf(b,sizeof(b),"%+.2f%%",pct);text_right(350,y+28,b,pct>=0?GREEN:RED,2);}
      }
      y+=rh+2;
    }
  }
  // Single full-width view toggle. No refresh button — prices are live.
  { const char*bl=selected_chart>=0||detail?"PRICES":"POSITIONS"; rect(16,400,336,36,BLUE); text_center(16,336,410,bl,WHITE,2); }
  flush_frame();
}
// draw() reads feed state owned by the network task, so serialize it with state_mux.
static void draw_locked(){ if(state_mux)xSemaphoreTake(state_mux,portMAX_DELAY); draw(); if(state_mux)xSemaphoreGive(state_mux); }
// Touch runs on its own task, polling the controller's touch registers directly
// every 10ms. Direct reads keep
// working through the FocalTech/CST "reports only on event" behavior, and because
// it's a separate task, sampling stays alive even while the UI task is mid
// frame-flush — so taps are no longer dropped. A new press is latched into
// tap_x/tap_y for the UI loop to consume. Both controllers use the FocalTech
// register layout: reg 0x02 = [count][xh][xl][yh][yl].
static void touch_task(void*){
  if(!i2c_bus){ ESP_LOGE(TAG,"touch task: no i2c bus"); vTaskDelete(nullptr); return; }
#if BOARD_IS_V1
  const uint8_t addr=0x38;   // FT5x06
#else
  const uint8_t addr=0x15;   // CST816S
#endif
  i2c_device_config_t c={};c.dev_addr_length=I2C_ADDR_BIT_LEN_7;c.device_address=addr;c.scl_speed_hz=400000;
  i2c_master_dev_handle_t dev=nullptr;
  if(i2c_master_bus_add_device(i2c_bus,&c,&dev)!=ESP_OK){ ESP_LOGE(TAG,"touch task: i2c add 0x%02x failed",addr); vTaskDelete(nullptr); return; }
  ESP_LOGI(TAG,"touch task polling 0x%02x",addr);
  bool down=false;
  while(true){
    bool pressed=false; int x=0,y=0;
#if BOARD_IS_V1
    bool ready=gpio_get_level(GPIO_NUM_21)==0;   // FT NACKs while idle; INT low = awake
#else
    bool ready=true;                              // CST816S answers whenever polled
#endif
    if(ready){
      uint8_t reg=0x02, buf[6]={0};
      if(i2c_master_transmit_receive(dev,&reg,1,buf,6,20)==ESP_OK){
        int num=buf[0]&0x0F;
        if(num>0&&num<=5){ int rx=((buf[1]&0x0F)<<8)|buf[2], ry=((buf[3]&0x0F)<<8)|buf[4];
          if(rx>=0&&rx<W&&ry>=0&&ry<H){ x=rx; y=ry; pressed=true; } }
      }
    }
    if(pressed&&!down){tap_y.store(y,std::memory_order_relaxed);tap_x.store(x,std::memory_order_release);}
    down=pressed;
    vTaskDelay(pdMS_TO_TICKS(10));
  }
}
struct HttpResponse { std::vector<char> body; bool overflow=false; };
static esp_err_t http_evt(esp_http_client_event_t *e){
  auto*r=static_cast<HttpResponse*>(e->user_data);
  if(e->event_id==HTTP_EVENT_ON_DATA&&e->data_len>0){
    if(r->body.size()+(size_t)e->data_len>MAX_FEED_BYTES){r->overflow=true;return ESP_FAIL;}
    const char*p=static_cast<const char*>(e->data);r->body.insert(r->body.end(),p,p+e->data_len);
  }
  return ESP_OK;
}
static bool fetch(){
  if(!wifi_up.load()){feed_status=ST_NOWIFI;data_dirty=true;return false;}
  RuntimeConfigSnapshot runtime=RuntimeConfig::GetInstance().Snapshot();
  if(!runtime.IsProvisioned()){feed_status=ST_UNCONFIGURED;data_dirty=true;return false;}

  HttpResponse response;
  std::string auth="Bearer "+runtime.bearer_token;
  esp_http_client_config_t cfg={};
  cfg.url=runtime.bridge_url.c_str();cfg.event_handler=http_evt;cfg.user_data=&response;
  cfg.timeout_ms=12000;cfg.disable_auto_redirect=true;
  if(runtime.bridge_url.rfind("https://",0)==0)cfg.crt_bundle_attach=esp_crt_bundle_attach;
  esp_http_client_handle_t h=esp_http_client_init(&cfg);
  if(!h){std::fill(auth.begin(),auth.end(),'\0');std::fill(runtime.bearer_token.begin(),runtime.bearer_token.end(),'\0');feed_status=ST_HTTPERR;feed_http_code=0;data_dirty=true;return false;}
  esp_http_client_set_header(h,"Authorization",auth.c_str());
  esp_http_client_set_header(h,"X-Device-ID",runtime.device_id.c_str());
  esp_http_client_set_header(h,"Accept","application/json");
  esp_http_client_set_header(h,"User-Agent","amoled-terminal/1");
  const esp_err_t err=esp_http_client_perform(h);
  const int code=esp_http_client_get_status_code(h);
  esp_http_client_cleanup(h);
  std::fill(auth.begin(),auth.end(),'\0');
  std::fill(runtime.bearer_token.begin(),runtime.bearer_token.end(),'\0');
  ESP_LOGI(TAG,"feed request status=%d result=%s bytes=%u",code,esp_err_to_name(err),(unsigned)response.body.size());
  if(response.overflow){feed_status=ST_TOO_LARGE;data_dirty=true;return false;}
  if(err!=ESP_OK||code!=200){feed_status=ST_HTTPERR;feed_http_code=code;data_dirty=true;return false;}

  response.body.push_back('\0');
  cJSON*d=cJSON_ParseWithLengthOpts(response.body.data(),response.body.size(),nullptr,true);
  if(!cJSON_IsObject(d)){if(d)cJSON_Delete(d);feed_status=ST_JSONERR;data_dirty=true;return false;}
  cJSON*schema=cJSON_GetObjectItemCaseSensitive(d,"schema_version");
  if(schema&&(!cJSON_IsNumber(schema)||schema->valueint!=1)){
    cJSON_Delete(d);feed_status=ST_JSONERR;data_dirty=true;return false;
  }
  // Fail closed: missing, duplicate, false, numeric, or string read_only values
  // are all unsafe.
  cJSON*ro=nullptr;int ro_count=0;
  for(cJSON*item=d->child;item;item=item->next)if(item->string&&strcmp(item->string,"read_only")==0){ro=item;ro_count++;}
  if(ro_count!=1||!cJSON_IsTrue(ro)){cJSON_Delete(d);feed_status=ST_UNSAFE;data_dirty=true;return false;}
  cJSON*prices=cJSON_GetObjectItemCaseSensitive(d,"prices");
  cJSON*price_history=cJSON_GetObjectItemCaseSensitive(d,"price_history");
  cJSON*candles=cJSON_GetObjectItemCaseSensitive(d,"candles");
  cJSON*positions=cJSON_GetObjectItemCaseSensitive(d,"positions");
  cJSON*portfolio=cJSON_GetObjectItemCaseSensitive(d,"portfolio");
  if(!cJSON_IsObject(prices)||!cJSON_IsObject(positions)||!cJSON_IsObject(portfolio)){
    cJSON_Delete(d);feed_status=ST_JSONERR;data_dirty=true;return false;
  }

  if(state_mux)xSemaphoreTake(state_mux,portMAX_DELAY);
  position_value=num(portfolio,"positions_value");
  total_pnl=num(portfolio,"unrealized_pnl");
  realized_pnl_today=num(portfolio,"realized_pnl_today");
  double refresh=num(d,"refresh_seconds");
  if(refresh>=2&&refresh<=3600)feed_refresh_seconds=(uint32_t)refresh;
  double history_step=num(d,"price_history_seconds");
  history_sample_seconds=history_step>=2&&history_step<=3600?(uint32_t)history_step:feed_refresh_seconds;
  double candle_step=num(d,"candle_interval_seconds");
  if(candle_step<=0)candle_step=num(d,"candles_interval_seconds");
  candle_interval_seconds=candle_step>=1&&candle_step<=604800?(uint32_t)candle_step:0;
  for(auto&a:assets){
    load_candles(a,candles);
    bool loaded=load_price_history(a,price_history);double price=num(prices,a.name);
    if(price>0&&std::isfinite(price)){a.price=price;if(!loaded)push_price(a,price);}
    a.pos=Position{};cJSON*p=cJSON_GetObjectItemCaseSensitive(positions,a.name);
    cJSON*open=cJSON_IsObject(p)?cJSON_GetObjectItemCaseSensitive(p,"open"):nullptr;
    if(cJSON_IsObject(p)&&!cJSON_IsFalse(open)){
      a.pos.open=true;cJSON*s=cJSON_GetObjectItemCaseSensitive(p,"side");
      if(cJSON_IsString(s)&&s->valuestring&&strlen(s->valuestring)<=10)a.pos.side=s->valuestring;
      a.pos.size=num(p,"contracts");if(a.pos.size==0)a.pos.size=num(p,"size");
      a.pos.entry=num(p,"entry");a.pos.pnl=num(p,"pnl");
    }
  }
  if(!candle_interval_seconds){
    uint64_t inferred=0;
    for(auto&a:assets)for(int i=1;i<a.candle_count;i++){
      int64_t delta=a.candles[i].timestamp-a.candles[i-1].timestamp;
      if(delta>0&&delta<=604800&&(!inferred||(uint64_t)delta<inferred))inferred=delta;
    }
    candle_interval_seconds=(uint32_t)inferred;
  }
  closed_today.clear();cJSON*closed=cJSON_GetObjectItemCaseSensitive(d,"closed_today");cJSON*item=nullptr;
  cJSON_ArrayForEach(item,closed){
    if(closed_today.size()>=20||!cJSON_IsObject(item))break;
    ClosedPosition p;cJSON*s=cJSON_GetObjectItemCaseSensitive(item,"symbol");
    if(cJSON_IsString(s)&&s->valuestring&&strlen(s->valuestring)<=10)p.symbol=s->valuestring;
    s=cJSON_GetObjectItemCaseSensitive(item,"side");
    if(cJSON_IsString(s)&&s->valuestring&&strlen(s->valuestring)<=10)p.side=s->valuestring;
    p.size=num(item,"contracts");if(p.size==0)p.size=num(item,"size");p.pnl=num(item,"pnl");
    closed_today.push_back(std::move(p));
  }
  last_ok_ms=esp_timer_get_time()/1000;feed_status=ST_UPDATED;
  if(state_mux)xSemaphoreGive(state_mux);
  cJSON_Delete(d);
  ESP_LOGI(TAG,"accepted read-only feed");
  data_dirty=true;return true;
}
static bool color_done(esp_lcd_panel_io_handle_t,esp_lcd_panel_io_event_data_t*,void*){ BaseType_t wake=pdFALSE; xSemaphoreGiveFromISR(tx_done,&wake); return wake==pdTRUE; }
static i2c_master_bus_handle_t ensure_i2c_bus(){
  if(i2c_bus)return i2c_bus;
  i2c_master_bus_config_t bc={};bc.i2c_port=I2C_NUM_0;bc.sda_io_num=GPIO_NUM_15;bc.scl_io_num=GPIO_NUM_14;bc.clk_source=I2C_CLK_SRC_DEFAULT;bc.glitch_ignore_cnt=7;bc.flags.enable_internal_pullup=1;
  ESP_ERROR_CHECK(i2c_new_master_bus(&bc,&i2c_bus));
  return i2c_bus;
}
// Per-variant panel power/reset. Both use TCA9554 outputs 0, 1, and 2 at 0x20,
// asserted before the first panel command; doing this after panel_init is too late.
// V1 additionally requires its AXP2101 rail setup at 0x34; V2 must NEVER receive
// those PMU writes — they can blank the CO5300 panel
// while every driver init still logs success.
static void panel_power_reset(){
  ensure_i2c_bus();
  ESP_ERROR_CHECK(esp_io_expander_new_i2c_tca9554(i2c_bus,ESP_IO_EXPANDER_I2C_TCA9554_ADDRESS_000,&io_expander));
  constexpr uint32_t mask=IO_EXPANDER_PIN_NUM_0|IO_EXPANDER_PIN_NUM_1|IO_EXPANDER_PIN_NUM_2;
  ESP_ERROR_CHECK(esp_io_expander_set_dir(io_expander,mask,IO_EXPANDER_OUTPUT));
#if BOARD_IS_V1
  ESP_ERROR_CHECK(esp_io_expander_set_dir(io_expander,IO_EXPANDER_PIN_NUM_4,IO_EXPANDER_INPUT));
  ESP_ERROR_CHECK(esp_io_expander_set_level(io_expander,mask,1));
  vTaskDelay(pdMS_TO_TICKS(100));
  ESP_ERROR_CHECK(esp_io_expander_set_level(io_expander,mask,0));
  vTaskDelay(pdMS_TO_TICKS(300));
  ESP_ERROR_CHECK(esp_io_expander_set_level(io_expander,mask,1));
  i2c_master_dev_handle_t axp;
  i2c_device_config_t axp_cfg={};axp_cfg.dev_addr_length=I2C_ADDR_BIT_LEN_7;axp_cfg.device_address=0x34;axp_cfg.scl_speed_hz=400000;
  ESP_ERROR_CHECK(i2c_master_bus_add_device(i2c_bus,&axp_cfg,&axp));
  static const uint8_t axp_seq[][2]={
    {0x22,0b110},{0x27,0x10},                       // PWRON>OFFLEVEL poweroff source, 4s hold
    {0x80,0x01},{0x90,0x00},{0x91,0x00},            // only DC1 on, all LDOs off
    {0x82,(3300-1500)/100},{0x92,(3300-500)/100},   // DC1 3.3V, ALDO1 3.3V
    {0x90,0x01},                                    // enable ALDO1
    {0x64,0x02},{0x61,0x02},{0x62,0x08},{0x63,0x01} // charger 4.1V / 50mA pre / 200mA / 25mA term
  };
  for(auto&rv:axp_seq){ uint8_t buf[2]={rv[0],rv[1]}; ESP_ERROR_CHECK(i2c_master_transmit(axp,buf,2,100)); }
  ESP_ERROR_CHECK(i2c_master_bus_rm_device(axp));
  ESP_LOGI(TAG,"V1 TCA9554+AXP2101 power/reset complete");
#else
  ESP_ERROR_CHECK(esp_io_expander_set_level(io_expander,mask,0));
  vTaskDelay(pdMS_TO_TICKS(20));
  ESP_ERROR_CHECK(esp_io_expander_set_level(io_expander,mask,1));
  vTaskDelay(pdMS_TO_TICKS(120));
  uint32_t levels=0;
  ESP_ERROR_CHECK(esp_io_expander_get_level(io_expander,mask,&levels));
  ESP_LOGI(TAG,"V2 TCA9554 power/reset complete: mask=0x%02lx levels=0x%02lx",(unsigned long)mask,(unsigned long)levels);
#endif
}
// Bring up the panel before PSRAM, touch, or Wi-Fi and show a brief color-bar
// hardware check. The stripe buffer is internal DMA memory.
static void phase1_display_bars(){
  panel_power_reset();
  tx_done=xSemaphoreCreateBinary(); if(!tx_done) abort();
  spi_bus_config_t sb={}; sb.sclk_io_num=11;sb.data0_io_num=4;sb.data1_io_num=5;sb.data2_io_num=6;sb.data3_io_num=7;sb.max_transfer_sz=W*TX_LINES*2; ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST,&sb,SPI_DMA_CH_AUTO));
  esp_lcd_panel_io_spi_config_t io={};io.cs_gpio_num=12;io.dc_gpio_num=-1;io.spi_mode=0;io.pclk_hz=40*1000*1000;io.trans_queue_depth=10;io.on_color_trans_done=color_done;io.user_ctx=nullptr;io.lcd_cmd_bits=32;io.lcd_param_bits=8;io.flags.quad_mode=true; ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST,&io,&lcd_io));
#if BOARD_IS_V1
  // SH8601 initialization with brightness set to 75% for immediate visibility.
  static const sh8601_lcd_init_cmd_t cmds[]={{0x11,(uint8_t[]){0x00},0,120},{0x44,(uint8_t[]){0x01,0xD1},2,0},{0x35,(uint8_t[]){0x00},1,0},{0x53,(uint8_t[]){0x20},1,10},{0x2A,(uint8_t[]){0x00,0x00,0x01,0x6F},4,0},{0x2B,(uint8_t[]){0x00,0x00,0x01,0xBF},4,0},{0x51,(uint8_t[]){0xBF},1,10},{0x29,(uint8_t[]){0x00},0,10}}; sh8601_vendor_config_t vc={};vc.init_cmds=cmds;vc.init_cmds_size=sizeof(cmds)/sizeof(cmds[0]);vc.flags.use_qspi_interface=1;esp_lcd_panel_dev_config_t pc={};pc.reset_gpio_num=GPIO_NUM_NC;pc.flags.reset_active_high=1;pc.rgb_ele_order=LCD_RGB_ELEMENT_ORDER_RGB;pc.bits_per_pixel=16;pc.vendor_config=&vc; ESP_ERROR_CHECK(esp_lcd_new_panel_sh8601(lcd_io,&pc,&panel)); ESP_ERROR_CHECK(esp_lcd_panel_reset(panel));ESP_ERROR_CHECK(esp_lcd_panel_init(panel));ESP_ERROR_CHECK(esp_lcd_panel_invert_color(panel,false));ESP_ERROR_CHECK(esp_lcd_panel_set_gap(panel,PANEL_X_GAP,0));ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel,true));
#else
  static const co5300_lcd_init_cmd_t cmds[]={{0xFE,(uint8_t[]){0x00},1,0},{0xC4,(uint8_t[]){0x80},1,0},{0x3A,(uint8_t[]){0x55},1,0},{0x35,(uint8_t[]){0x00},1,0},{0x53,(uint8_t[]){0x20},1,0},{0x51,(uint8_t[]){0xFF},1,0},{0x63,(uint8_t[]){0xFF},1,0},{0x2A,(uint8_t[]){0x00,0x00,0x01,0x6F},4,0},{0x2B,(uint8_t[]){0x00,0x00,0x01,0xBF},4,0},{0x11,nullptr,0,100},{0x29,nullptr,0,0}}; co5300_vendor_config_t vc={};vc.init_cmds=cmds;vc.init_cmds_size=sizeof(cmds)/sizeof(cmds[0]);vc.flags.use_qspi_interface=1;esp_lcd_panel_dev_config_t pc={};pc.reset_gpio_num=GPIO_NUM_NC;pc.rgb_ele_order=LCD_RGB_ELEMENT_ORDER_RGB;pc.bits_per_pixel=16;pc.vendor_config=&vc; ESP_ERROR_CHECK(esp_lcd_new_panel_co5300(lcd_io,&pc,&panel)); ESP_ERROR_CHECK(esp_lcd_panel_reset(panel));ESP_ERROR_CHECK(esp_lcd_panel_init(panel));ESP_ERROR_CHECK(esp_lcd_panel_set_gap(panel,PANEL_X_GAP,0));ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(panel,true));
#endif
  static DMA_ATTR uint16_t bars[W*TX_LINES];
  static const uint16_t colors[8]={0xFFFF,0xFFE0,0x07FF,0x07E0,0xF81F,0xF800,0x001F,0x0000};
  for(int y=0;y<H;y+=TX_LINES){
    for(int r=0;r<TX_LINES;r++) for(int x=0;x<W;x++) bars[r*W+x]=__builtin_bswap16(colors[(x*8)/W]);
    ESP_ERROR_CHECK(esp_lcd_panel_draw_bitmap(panel,0,y,W,y+TX_LINES,bars));
    if(xSemaphoreTake(tx_done,pdMS_TO_TICKS(2000))!=pdTRUE){ESP_LOGE(TAG,"display transfer timeout y=%d",y);return;}
  }
  ESP_LOGI(TAG,"display initialized");
}
static void init_rest(){
  i2c_master_bus_handle_t bus=ensure_i2c_bus();
  fb=(uint16_t*)heap_caps_malloc(W*H*2,MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
  txbuf=(uint16_t*)heap_caps_malloc(W*TX_LINES*2,MALLOC_CAP_DMA|MALLOC_CAP_INTERNAL);
  if(!fb||!txbuf)abort();
#if !BOARD_IS_V1
  ESP_ERROR_CHECK(esp_lcd_panel_co5300_set_brightness(panel,75));
#endif
  esp_lcd_panel_io_handle_t touch_io; esp_lcd_panel_io_i2c_config_t touch_io_cfg={};
#if BOARD_IS_V1
  touch_io_cfg.dev_addr=ESP_LCD_TOUCH_IO_I2C_FT5x06_ADDRESS;
#else
  touch_io_cfg.dev_addr=ESP_LCD_TOUCH_IO_I2C_CST816S_ADDRESS;
#endif
  touch_io_cfg.control_phase_bytes=1;touch_io_cfg.lcd_cmd_bits=8;touch_io_cfg.flags.disable_control_phase=1;touch_io_cfg.scl_speed_hz=400000;ESP_ERROR_CHECK(esp_lcd_new_panel_io_i2c(bus,&touch_io_cfg,&touch_io));esp_lcd_touch_config_t touch_cfg={};touch_cfg.x_max=W;touch_cfg.y_max=H;touch_cfg.rst_gpio_num=GPIO_NUM_NC;touch_cfg.int_gpio_num=GPIO_NUM_21;touch_cfg.levels.reset=0;touch_cfg.levels.interrupt=0;
#if BOARD_IS_V1
  // FT-family quirk handling: retry with an INT-pin wake pulse (holding INT low
  // briefly wakes the controller from hibernate). Touch failure must never abort
  // the boot — the display keeps working without it.
  {
    esp_err_t terr=esp_lcd_touch_new_i2c_ft5x06(touch_io,&touch_cfg,&touch);
    for(int attempt=1;terr!=ESP_OK&&attempt<=2;attempt++){
      ESP_LOGW(TAG,"FT5x06 init failed (%s), wake attempt %d",esp_err_to_name(terr),attempt);
      touch=nullptr;
      gpio_config_t gi={.pin_bit_mask=1ULL<<GPIO_NUM_21,.mode=GPIO_MODE_OUTPUT,.pull_up_en=GPIO_PULLUP_DISABLE,.pull_down_en=GPIO_PULLDOWN_DISABLE,.intr_type=GPIO_INTR_DISABLE};
      gpio_config(&gi); gpio_set_level(GPIO_NUM_21,0); vTaskDelay(pdMS_TO_TICKS(15)); gpio_set_level(GPIO_NUM_21,1); vTaskDelay(pdMS_TO_TICKS(120));
      gpio_reset_pin(GPIO_NUM_21);
      terr=esp_lcd_touch_new_i2c_ft5x06(touch_io,&touch_cfg,&touch);
    }
    if(terr!=ESP_OK){ touch=nullptr; ESP_LOGE(TAG,"touch unavailable (%s); continuing display-only",esp_err_to_name(terr)); }
  }
#else
  if(esp_lcd_touch_new_i2c_cst816s(touch_io,&touch_cfg,&touch)!=ESP_OK){ touch=nullptr; ESP_LOGE(TAG,"touch unavailable; continuing display-only"); }
#endif
  ESP_LOGI(TAG,"touch %s",touch?"ready":"unavailable");
  gpio_config_t gb={.pin_bit_mask=1ULL<<GPIO_NUM_0,.mode=GPIO_MODE_INPUT,.pull_up_en=GPIO_PULLUP_ENABLE,.pull_down_en=GPIO_PULLDOWN_DISABLE,.intr_type=GPIO_INTR_DISABLE}; gpio_config(&gb);
  update_battery();   // seed the power indicator before the first UI frame
}
// Network fetch runs on its own task so the blocking HTTP round trip never stalls
// touch sampling or rendering in the UI loop. It writes shared feed state under
// state_mux (see fetch()) and raises data_dirty for the UI loop to redraw.
static void fetch_task(void*){
  uint64_t last=0;
  while(true){
    const uint64_t now=esp_timer_get_time()/1000;
    const uint32_t interval_ms=feed_refresh_seconds?feed_refresh_seconds*1000u:REFRESH_MS;
    const bool requested=force_fetch.exchange(false);
    // A physically opened setup/OTA AP does not pause an already connected feed.
    if(requested||last==0||now-last>=interval_ms){last=now;fetch();}
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}
extern "C" void app_main(){
  ESP_LOGI(TAG,"board variant: %s",BOARD_IS_V1?"v1 SH8601/FT5x06/AXP2101":"v2 CO5300/CST820");
  phase1_display_bars();
  vTaskDelay(pdMS_TO_TICKS(BOOT_SPLASH_MS));

  esp_err_t err=nvs_flash_init();
  if(err==ESP_ERR_NVS_NO_FREE_PAGES||err==ESP_ERR_NVS_NEW_VERSION_FOUND){
    ESP_ERROR_CHECK(nvs_flash_erase());err=nvs_flash_init();
  }
  ESP_ERROR_CHECK(err);
  ESP_ERROR_CHECK(RuntimeConfig::GetInstance().Initialize());
  err=OnboardingMetadata::GetInstance().Initialize();
  if(err!=ESP_OK&&err!=ESP_ERR_NOT_FOUND)
    ESP_LOGW(TAG,"unable to read USB onboarding metadata: %s",esp_err_to_name(err));
  init_rest();
  state_mux=xSemaphoreCreateMutex();if(!state_mux)abort();

  err=esp_ota_mark_app_valid_cancel_rollback();
  if(err!=ESP_OK&&err!=ESP_ERR_OTA_ROLLBACK_INVALID_STATE)
    ESP_LOGW(TAG,"unable to confirm OTA image: %s",esp_err_to_name(err));

  auto& network=NetworkPortal::GetInstance();
  network.Initialize(
    [](bool connected){wifi_up=connected;if(connected)force_fetch=true;data_dirty=true;},
    [](){data_dirty=true;});
  draw_locked();
  xTaskCreate(fetch_task,"feed",12288,nullptr,4,nullptr);
  xTaskCreate(touch_task,"touch",3072,nullptr,6,nullptr);

  uint64_t last_draw=esp_timer_get_time()/1000,button_at=0,last_batt=0;
  bool button_down=false,ota_hold_handled=false;
  bool shown_portal=network.IsPortalActive(),shown_armed=network.IsOtaArmed();
  // Touch has its own 10 ms task; this loop consumes latched taps and never blocks
  // on network I/O. Frame flushes occur only when state changes or once per second.
  while(true){
    const uint64_t now=esp_timer_get_time()/1000;
    bool need_draw=false;
    const bool portal=network.IsPortalActive(),armed=network.IsOtaArmed();
    if(portal!=shown_portal||armed!=shown_armed){shown_portal=portal;shown_armed=armed;need_draw=true;}
    if(data_dirty.exchange(false))need_draw=true;
    const int tx=tap_x.exchange(-1,std::memory_order_acquire);
    const int ty=tap_y.load(std::memory_order_relaxed);
    if(tx>=0){
      tap_y=-1;
      if(!portal&&screen_on){
        if(ty>=390){if(selected_chart>=0)selected_chart=-1;else detail=!detail;need_draw=true;}
        else if(selected_chart>=0&&ty>=54&&ty<390){selected_chart=(selected_chart+(tx<W/2?4:1))%5;need_draw=true;}
        else if(!detail&&ty>=54&&ty<390){for(int k=0;k<px_row_n;k++)if(ty>=px_row_y[k]&&ty<px_row_y[k]+px_row_h[k]){selected_chart=px_row_asset[k];need_draw=true;break;}}
      }
    }
    const bool pressed=gpio_get_level(GPIO_NUM_0)==0;
    if(pressed&&!button_down){button_at=now;ota_hold_handled=false;}
    if(pressed&&!ota_hold_handled&&now-button_at>=10000){
      if(!screen_on)set_screen(true);
      network.ArmOta();ota_hold_handled=true;need_draw=true;
    }
    if(!pressed&&button_down&&!ota_hold_handled){
      const uint64_t held=now-button_at;
      if(held>=750){set_screen(!screen_on);if(screen_on)need_draw=true;}
      else if(!portal&&screen_on){if(selected_chart>=0)selected_chart=-1;else detail=!detail;need_draw=true;}
    }
    button_down=pressed;
    if(now-last_batt>=5000){update_battery();last_batt=now;need_draw=true;}
    if(now-last_draw>=1000)need_draw=true;
    if(need_draw&&screen_on){draw_locked();last_draw=now;}
    vTaskDelay(pdMS_TO_TICKS(20));
  }
}
