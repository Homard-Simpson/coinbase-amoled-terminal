// Host framebuffer capture for the production Coinbase AMOLED renderer.
//
// The drawing primitives, palette, state structs, and draw() implementation below
// are copied from the production ESP32 renderer. Hardware-only services are stubbed:
// the setup portal is inactive, feed state is healthy, bridge-local time is fixed,
// and flush_frame writes
// the exact 368x448 RGB565 framebuffer instead of sending it to the panel.
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "bollinger_bands.h"
#include "key_levels.h"
#include "../../firmware/main/ui_helpers.h"
#define PROGMEM
#include "glcdfont.h"

static constexpr int W=368,H=448;
static constexpr int HISTORY_SAMPLES=60;
static constexpr int CANDLE_SAMPLES=36;
static constexpr uint32_t STALE_MS=20000;
static uint16_t *fb;
static bool wifi_up=true, detail=false;
static int selected_chart=-1;
static uint32_t history_sample_seconds=3600;
static uint64_t last_ok_ms=10000;
static std::string display_time="09:41 PM";
static int px_row_y[5],px_row_h[5],px_row_asset[5],px_row_n=0;
enum { ST_STARTING=0, ST_UPDATED, ST_NOWIFI, ST_HTTPERR, ST_JSONERR, ST_UNSAFE, ST_ACCOUNT_STALE };
static int feed_status=ST_UPDATED, feed_http_code=0;
static bool privacy_mode=true;
struct Position { bool open=false; std::string side="-"; double size=0,entry=0,pnl=0; };
struct ClosedPosition { std::string symbol="-",side="-"; double size=0,pnl=0; };
struct Candle { int64_t timestamp=0; double open=0,high=0,low=0,close=0,volume=0; };
struct Asset {
  const char *name; double price=0; Position pos;
  double history[HISTORY_SAMPLES]={}; uint8_t history_count=0,history_head=0;
  Candle candles[CANDLE_SAMPLES]={}; uint8_t candle_count=0;
  KeyLevels key_levels;
  explicit Asset(const char*n):name(n){}
};
static Asset assets[]={Asset("BTC"),Asset("SOL"),Asset("XLM"),Asset("HYPE"),Asset("ETH")};
static std::vector<ClosedPosition> closed_today;
static double position_value=0, total_pnl=0, realized_pnl_today=0;
struct Battery { bool present=false; int level=0; bool charging=false, done=false, vbus=false; };
static Battery g_batt;

class NetworkPortal {
 public:
  static NetworkPortal& GetInstance(){ static NetworkPortal instance; return instance; }
  bool IsPortalActive() const { return false; }
  bool IsOtaArmed() const { return false; }
  const std::string& GetApSsid() const { static const std::string value=""; return value; }
  const std::string& GetOtaCode() const { static const std::string value=""; return value; }
};
static int64_t esp_timer_get_time(){ return 10000LL*1000LL; }
static std::string output_path;
static void flush_frame(){
  FILE *out=std::fopen(output_path.c_str(),"wb");
  if(!out){std::perror(output_path.c_str());std::exit(2);}
  if(std::fwrite(fb,sizeof(uint16_t),W*H,out)!=(size_t)(W*H)){std::perror("fwrite");std::exit(2);}
  std::fclose(out);
}

static uint16_t rgb(uint8_t r,uint8_t g,uint8_t b){ return __builtin_bswap16(((r&0xF8)<<8)|((g&0xFC)<<3)|(b>>3)); }
static const uint16_t BLACK=rgb(5,8,15),CARD=rgb(18,24,38),GRID=rgb(45,57,78),MUTED=rgb(190,198,214),WHITE=rgb(245,247,250),GREEN=rgb(48,209,88),RED=rgb(255,69,58),BLUE=rgb(55,126,255),AMBER=rgb(255,180,0),BB_UPPER=rgb(55,220,255),BB_LOWER=rgb(180,105,255),BB_MIDDLE=rgb(105,125,155),AXIS_BLUE=rgb(125,175,210);
static void rect(int x,int y,int w,int h,uint16_t c){ x=std::max(0,x); y=std::max(0,y); w=std::min(w,W-x); h=std::min(h,H-y); for(int yy=y;yy<y+h;yy++) std::fill(fb+yy*W+x,fb+yy*W+x+w,c); }
static int text_width(const char*s,int scale=2){ scale=std::max(2,scale); return (int)strlen(s)*6*scale; }
static void text(int x,int y,const char*s,uint16_t c,int scale=2){ scale=std::max(2,scale); for(;*s;s++,x+=6*scale){ unsigned ch=(unsigned char)*s; if(ch<32||ch>127) ch='?'; for(int i=0;i<5;i++){ uint8_t col=font[ch*5+i]; for(int j=0;j<8;j++) if(col&(1<<j)) rect(x+i*scale,y+j*scale,scale,scale,c); } } }
static void text_right(int right,int y,const char*s,uint16_t c,int scale=2){ text(std::max(0,right-text_width(s,scale)),y,s,c,scale); }
static void text_center(int left,int width,int y,const char*s,uint16_t c,int scale=2){ text(left+std::max(0,(width-text_width(s,scale))/2),y,s,c,scale); }
static void text_bold(int x,int y,const char*s,uint16_t c,int scale=2){ text(x,y,s,c,scale); text(x+1,y,s,c,scale); }
static void to_upper(char*s){ for(;*s;s++) if(*s>='a'&&*s<='z') *s=(char)(*s-'a'+'A'); }
static void fmt_money(char *b,size_t n,double v){ double a=fabs(v); if(a>=10000) snprintf(b,n,"$%.0f",v); else if(a>=100) snprintf(b,n,"$%.2f",v); else if(a>=1) snprintf(b,n,"$%.3f",v); else snprintf(b,n,"$%.5f",v); }
static void fmt_entry_money(char *b,size_t n,double v){ double a=fabs(v); if(a>=100) snprintf(b,n,"$%.2f",v); else if(a>=1) snprintf(b,n,"$%.3f",v); else snprintf(b,n,"$%.5f",v); }
static void draw_key_level_row(const Asset&a,int left,int right,int y){
  char price[24],label[28]; double support=0,resistance=0;
  nearest_key_levels(a.key_levels,a.price,support,resistance);
  if(support>0){fmt_money(price,sizeof(price),support);snprintf(label,sizeof(label),"S %s",price);text(left,y,label,GREEN,2);}
  else text(left,y,"S --",MUTED,2);
  if(resistance>0){fmt_money(price,sizeof(price),resistance);snprintf(label,sizeof(label),"R %s",price);text_right(right,y,label,RED,2);}
  else text_right(right,y,"R --",MUTED,2);
}
static void pixel(int x,int y,uint16_t c){ if(x>=0&&x<W&&y>=0&&y<H)fb[y*W+x]=c; }
static void draw_line(int x0,int y0,int x1,int y1,uint16_t c,int thickness=1){
  int dx=abs(x1-x0),sx=x0<x1?1:-1,dy=-abs(y1-y0),sy=y0<y1?1:-1,err=dx+dy;
  while(true){ for(int yy=0;yy<thickness;yy++)pixel(x0,y0+yy,c); if(x0==x1&&y0==y1)break; int e2=2*err; if(e2>=dy){err+=dy;x0+=sx;} if(e2<=dx){err+=dx;y0+=sy;} }
}
static double history_at(const Asset&a,int i){ int start=(a.history_head+HISTORY_SAMPLES-a.history_count)%HISTORY_SAMPLES; return a.history[(start+i)%HISTORY_SAMPLES]; }
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
static bool candle_bounds(const Asset&a,double&lo,double&hi,double&max_volume){
  if(!a.candle_count)return false;
  lo=a.candles[0].low; hi=a.candles[0].high; max_volume=0;
  for(int i=0;i<a.candle_count;i++){ lo=std::min(lo,a.candles[i].low); hi=std::max(hi,a.candles[i].high); max_volume=std::max(max_volume,a.candles[i].volume); }
  return true;
}
static constexpr double ENTRY_NEAR_FRAC=0.25;
static constexpr double ENTRY_EDGE_PAD_FRAC=0.02;
static bool entry_in_view(double entry,double&lo,double&hi){
  if(!(entry>0)||!std::isfinite(entry))return false;
  double range=hi-lo; if(!(range>0))return false;
  if(entry>=lo&&entry<=hi)return true;
  if(entry>hi&&entry-hi<=range*ENTRY_NEAR_FRAC){hi=entry+range*ENTRY_EDGE_PAD_FRAC;return true;}
  if(entry<lo&&lo-entry<=range*ENTRY_NEAR_FRAC){lo=entry-range*ENTRY_EDGE_PAD_FRAC;return true;}
  return false;
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
static void draw_battery(int x,int y){
  int bw=40,bh=20,pct=g_batt.level;
  uint16_t lvlcol=!g_batt.present?MUTED:(pct>=50?GREEN:pct>=20?AMBER:RED);
  uint16_t bord=g_batt.charging?BLUE:lvlcol;
  rect(x,y,bw,bh,bord); rect(x+2,y+2,bw-4,bh-4,BLACK);
  rect(x+bw,y+bh/2-4,4,8,bord);
  if(g_batt.present){ int fw=(bw-6)*pct/100; if(fw<0)fw=0; if(fw>bw-6)fw=bw-6; rect(x+3,y+3,fw,bh-6,lvlcol); }
  if(g_batt.charging){ int cx=x+bw/2; draw_line(cx+4,y+3,cx-3,y+bh/2,WHITE,2); draw_line(cx-3,y+bh/2,cx+3,y+bh/2,WHITE,2); draw_line(cx+3,y+bh/2,cx-4,y+bh-3,WHITE,2); }
  char lb[16];
  if(g_batt.present)snprintf(lb,sizeof(lb),"%d%%",pct);
  else if(g_batt.vbus)snprintf(lb,sizeof(lb),"USB");
  else snprintf(lb,sizeof(lb),"--");
  text(x+bw+10,y+2,lb,g_batt.charging?BLUE:(g_batt.present?WHITE:MUTED),2);
}

// Kept in a separate include so this file can be mechanically compared with the
// production draw() implementation while capture data remains independently public.
#include "production_draw.inc"
#include "capture_data.h"

int main(int argc,char**argv){
  if(argc!=3){std::fprintf(stderr,"usage: %s prices|positions|chart output.rgb565\n",argv[0]);return 2;}
  fb=(uint16_t*)std::calloc(W*H,sizeof(uint16_t));
  if(!fb){std::perror("calloc");return 2;}
  load_capture_data();
  std::string page=argv[1];
  if(page=="prices"){selected_chart=-1;detail=false;privacy_mode=true;}
  else if(page=="positions"){selected_chart=-1;detail=true;privacy_mode=true;}
  else if(page=="chart"){selected_chart=0;detail=false;privacy_mode=true;}
  else {std::fprintf(stderr,"unknown page: %s\n",argv[1]);return 2;}
  output_path=argv[2];
  draw();
  std::free(fb);
  return 0;
}
