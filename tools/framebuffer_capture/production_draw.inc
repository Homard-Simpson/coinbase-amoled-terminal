static void draw(){
  rect(0,0,W,H,BLACK); char b[64];
  auto& network=NetworkPortal::GetInstance();
  if(network.IsPortalActive()){
    if(privacy_mode)text_right(352,8,"PRIVATE",AMBER,2);
    text(20,24,"COINBASE SETUP",WHITE,3);
    text(20,82,"CONNECT WI-FI:",MUTED,2);
    text(20,112,network.GetApSsid().c_str(),BLUE,2);
    text(20,158,"OPEN:",MUTED,2); text(20,186,"http://192.168.4.1",WHITE,2);
    text(20,238,"SAVE WI-FI TO RESTART",MUTED,2);
    if(network.IsOtaArmed()){
      text(20,302,"OTA ARMED - 5 MIN",AMBER,2);
      snprintf(b,sizeof(b),"CODE %s",network.GetOtaCode().c_str()); text(20,336,b,WHITE,3);
    } else { text(20,302,"OTA LOCKED",GREEN,2); text(20,332,"HOLD BOOT 10S TO ARM",MUTED,2); }
    text(20,406,"AP CLIENTS ONLY",MUTED,2);
    flush_frame();
    return;
  }
  uint64_t now=esp_timer_get_time()/1000; bool stale=!last_ok_ms||now-last_ok_ms>STALE_MS;
  constexpr TopBarAnchors top_bar=top_bar_anchors(W);
  draw_battery(top_bar.left,10);
  bool feed_problem=feed_status!=ST_UPDATED&&feed_status!=ST_STARTING;
  char status[24]{};
  if(stale||!wifi_up||feed_problem){
    if(stale)snprintf(status,sizeof(status),"STALE");
    else if(!wifi_up)snprintf(status,sizeof(status),"OFFLINE");
    else if(feed_status==ST_HTTPERR)snprintf(status,sizeof(status),"HTTP %d",feed_http_code);
    else if(feed_status==ST_JSONERR)snprintf(status,sizeof(status),"JSON ERR");
    else if(feed_status==ST_UNSAFE)snprintf(status,sizeof(status),"UNSAFE");
    else if(feed_status==ST_ACCOUNT_STALE)snprintf(status,sizeof(status),"ACCT STALE");
    else if(feed_status==ST_NOWIFI)snprintf(status,sizeof(status),"NO WIFI");
    else snprintf(status,sizeof(status),"FEED ERR");
  } else if(privacy_mode)snprintf(status,sizeof(status),"PRIVATE");
  if(status[0])text_center(120,132,12,status,AMBER,2);
  text_right(top_bar.right,12,display_time.c_str(),AXIS_BLUE,2);
  int top=58;
  if(selected_chart>=0){
    auto&a=assets[selected_chart];
    rect(16,top,336,338,CARD);
    text_bold(28,top+8,a.name,WHITE,3);
    fmt_money(b,sizeof(b),a.price); text(28+(int)strlen(a.name)*18+12,top+8,b,AMBER,3);
    double pct=chart_change_pct(a); snprintf(b,sizeof(b),"%+.2f%%",pct); text_right(340,top+14,b,pct>=0?GREEN:RED,2);
    // Reserve a compact left gutter for price labels; chart marks never draw there.
    int gx=94,gy=top+50,gw=242; char t[80];
    if(a.candle_count){
      // Volume candles: body width represents each candle's volume relative to
      // the highest-volume candle in the visible window. No separate volume bars.
      int price_h=224;
      double candle_lo=0,candle_hi=0,max_volume=0; candle_bounds(a,candle_lo,candle_hi,max_volume);
      double closes[CANDLE_SAMPLES]={}; BollingerPoint bands[CANDLE_SAMPLES]={};
      for(int i=0;i<a.candle_count;i++)closes[i]=a.candles[i].close;
      compute_bollinger_bands(closes,a.candle_count,bands,CANDLE_SAMPLES);
      // Only sane, nearby BB20 values may expand the natural market range. This
      // prevents corrupt math/data from flattening candles and also avoids drawing
      // a clamped line along the chart edge.
      bool band_visible[CANDLE_SAMPLES]={};
      double lo=candle_lo,hi=candle_hi;
      if(a.price>0&&std::isfinite(a.price)){lo=std::min(lo,a.price);hi=std::max(hi,a.price);}
      for(int i=0;i<a.candle_count;i++)if(bollinger_point_near_range(bands[i],candle_lo,candle_hi)){
        band_visible[i]=true; lo=std::min(lo,bands[i].lower); hi=std::max(hi,bands[i].upper);
      }
      double range=hi-lo;
      if(range<1e-9){double pad=std::max(fabs(hi)*0.0005,1e-6);lo-=pad;hi+=pad;}
      else {double pad=range*0.04;lo-=pad;hi+=pad;}
      // Entry no longer forces the scale; see entry_in_view for the near-range policy.
      bool show_entry=!privacy_mode&&a.pos.open&&entry_in_view(a.pos.entry,lo,hi);
      for(int i=0;i<=4;i++){int yy=gy+price_h*i/4;draw_line(gx,yy,gx+gw-1,yy,GRID);char axis[16];format_axis_price(axis,sizeof(axis),chart_level_value(lo,hi,i,4));text_right(gx-8,yy-7,axis,AXIS_BLUE,2);}
      auto py=[&](double v){double n=(v-lo)/(hi-lo);n=std::max(0.0,std::min(1.0,n));return gy+price_h-1-(int)lround(n*(price_h-1));};
      auto px=[&](int i){return gx+((2*i+1)*gw)/(2*a.candle_count);};
      bool any_band=false;
      for(int i=1;i<a.candle_count;i++)if(band_visible[i-1]&&band_visible[i]){
        draw_line(px(i-1),py(bands[i-1].upper),px(i),py(bands[i].upper),BB_UPPER);
        draw_line(px(i-1),py(bands[i-1].lower),px(i),py(bands[i].lower),BB_LOWER);
        draw_line(px(i-1),py(bands[i-1].middle),px(i),py(bands[i].middle),BB_MIDDLE);
        any_band=true;
      }
      if(any_band){rect(gx+gw-50,gy+3,50,18,CARD);text_right(gx+gw,gy+4,"BB20",BB_UPPER,2);}
      int entry_y=-1;
      if(show_entry){
        entry_y=py(a.pos.entry);
        for(int X=gx;X<gx+gw;X+=10)draw_line(X,entry_y,std::min(X+4,gx+gw-1),entry_y,AMBER);
      }
      int slot=std::max(1,gw/(int)a.candle_count);
      int max_body_w=std::max(1,std::min(11,slot-1));
      if(!(max_body_w&1))max_body_w--;
      for(int i=0;i<a.candle_count;i++){
        const Candle&cd=a.candles[i]; int cx=px(i);
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
      // Freed chart footer row: durable daily-pivot levels do not affect scale.
      draw_key_level_row(a,gx,gx+gw,yb+24);
    } else {
      // Legacy/partial feeds retain the former close-only expanded line chart.
      int gh=188; double lo=0,hi=0; bool hb=history_bounds(a,lo,hi);
      if(!hb){lo=0;hi=1;}
      if(fabs(hi-lo)<1e-9){double pad=std::max(fabs(hi)*0.0005,1e-6);lo-=pad;hi+=pad;}
      // Same policy as the candle chart: entry never forces the scale.
      bool show_entry=!privacy_mode&&hb&&a.pos.open&&entry_in_view(a.pos.entry,lo,hi);
      for(int i=0;i<=4;i++){int yy=gy+gh*i/4;draw_line(gx,yy,gx+gw-1,yy,GRID);char axis[16];format_axis_price(axis,sizeof(axis),chart_level_value(lo,hi,i,4));text_right(gx-8,yy-7,axis,AXIS_BLUE,2);}
      auto py=[&](double v){double n=(v-lo)/(hi-lo);n=std::max(0.0,std::min(1.0,n));return gy+gh-1-(int)lround(n*(gh-1));};
      if(show_entry){int ey=py(a.pos.entry);for(int X=gx;X<gx+gw;X+=10)draw_line(X,ey,std::min(X+4,gx+gw-1),ey,AMBER);text(gx+2,ey-16,"ENTRY",AMBER,2);}
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
      draw_key_level_row(a,gx,gx+gw,yb+48);
    }
  } else if(detail){
    // Portfolio summary now lives only on the POSITIONS page.
    rect(16,top,336,64,CARD);
    text(28,top+8,"OPEN VALUE",MUTED,2);
    if(privacy_mode){
      text(28,top+32,"$********",WHITE,3);
      text_right(340,top+8,"UPL ********",MUTED,2);
      text_right(340,top+40,"RPL ********",MUTED,2);
    } else {
      fmt_money(b,sizeof(b),position_value); text(28,top+32,b,WHITE,3);
      snprintf(b,sizeof(b),"UPL %+.2f",total_pnl); text_right(340,top+8,b,total_pnl>=0?GREEN:RED,2);
      snprintf(b,sizeof(b),"RPL %+.2f",realized_pnl_today); text_right(340,top+40,b,realized_pnl_today>=0?GREEN:RED,2);
    }
    int y=top+72;
    if(privacy_mode){
      text(16,y,"ACCOUNT EXPOSURE",WHITE,2); y+=28;
      rect(16,y,336,112,CARD);
      text(28,y+12,"POSITIONS  ********",MUTED,2);
      text(28,y+40,"QUANTITY   ********",MUTED,2);
      text(28,y+68,"ENTRY/P&L  ********",MUTED,2);
      text(28,y+96,"CLOSED     ********",MUTED,2);
    } else {
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
        char entry[24]; fmt_entry_money(entry,sizeof(entry),a.pos.entry); snprintf(b,sizeof(b),"%.4g @ %s",a.pos.size,entry); text(28,y+34,b,MUTED,2); // size @ live average entry, always precise enough to see changes
        snprintf(b,sizeof(b),"U%+.2f",a.pos.pnl); text_right(350,y+34,b,a.pos.pnl>=0?GREEN:RED,2);
        y+=60; shown++;
      }
      if(open_total>shown){ snprintf(b,sizeof(b),"+%d MORE",open_total-shown); text(24,y,b,AMBER,2); y+=24; }
      if(y+40<392){
        snprintf(b,sizeof(b),"CLOSED TODAY %u",(unsigned)closed_today.size()); text(16,y,b,WHITE,2); y+=24;
        if(closed_today.empty())text(24,y,"NONE YET",MUTED,2);
        else{ int cs=0; for(auto&p:closed_today){ if(y+38>392)break; rect(16,y,336,36,CARD); char sd[12]; snprintf(sd,sizeof(sd),"%s",p.side.c_str()); to_upper(sd); snprintf(b,sizeof(b),"%s %s",p.symbol.c_str(),sd); text(24,y+4,b,WHITE,2); snprintf(b,sizeof(b),"R%+.2f",p.pnl); text_right(350,y+4,b,p.pnl>=0?GREEN:RED,2); snprintf(b,sizeof(b),"SIZE %.4g",p.size); text(24,y+20,b,MUTED,2); y+=40; cs++; } if((int)closed_today.size()>cs&&y+16<=392){snprintf(b,sizeof(b),"+%u MORE",(unsigned)closed_today.size()-cs);text(24,y,b,AMBER,2);} }
      }
    }
  } else {
    // PRICES page: open positions get taller/bolder rows with an amber live price.
    int y=top; px_row_n=0;
    for(int i=0;i<5;i++){ auto&a=assets[i]; bool open=!privacy_mode&&a.pos.open; int rh=open?64:50;
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
        text(24,y+28,privacy_mode?"MARKET":"FLAT",MUTED,2);
        double pct=history_change_pct(a); if(a.history_count>=2){snprintf(b,sizeof(b),"%+.2f%%",pct);text_right(350,y+28,b,pct>=0?GREEN:RED,2);}
      }
      y+=rh+2;
    }
  }
  // Single full-width view toggle. No refresh button — prices are live.
  { const char*bl=selected_chart>=0||detail?"PRICES":"POSITIONS"; rect(16,400,336,36,BLUE); text_center(16,336,410,bl,WHITE,2); }
  flush_frame();
}
