// Zaman SPA — API client, router, live updates
const API = '';
const KEY = localStorage.getItem('zaman_api_key') || '';

function headers() {
  const h = {'Accept':'application/json'};
  if (KEY) h['X-API-Key'] = KEY;
  return h;
}
async function api(path) {
  try {
    const r = await fetch(API+path, {headers:headers()});
    if (!r.ok) return null;
    return await r.json();
  } catch(e) { return null; }
}
function loadingCard(msg){return '<div class="card p-4 t-sm" style="color:var(--z-dim)">'+(msg||'Loading...')+'</div>';}
function errorCard(msg){return '<div class="card p-4 t-sm c-err">'+(msg||'Failed to load data.')+'</div>';}

// Format numbers: 1234 → "1,234", 1234567 → "1.2M"
function fmt(v){if(v==null)return'0';if(typeof v!=='number')v=Number(v);if(isNaN(v))return'0';if(v>=1e6)return(v/1e6).toFixed(1)+'M';if(v>=1e4)return(v/1e3).toFixed(1)+'k';return v.toLocaleString();}

// Semantic color: only ok/warn/err/muted — no rainbow
function asrColor(v){return v>=70?'c-ok':v>=40?'c-warn':'c-err';}
function errColor(v){return v>0?'c-err':'c-ok';}
function h(s) { if (s==null) return ''; const d=document.createElement('div'); d.textContent=String(s); return d.innerHTML; }
function n(o,k) { return o&&o[k]!=null?o[k]:0; }

// Global node names — loaded once, used everywhere
window._nodeNames={};
(async()=>{try{const r=await fetch('/web/node-names',{headers:headers()});if(r.ok)window._nodeNames=await r.json();}catch(e){}})();
function agentName(agent){if(!agent)return'';const name=window._nodeNames[agent];return name?name:''+agent;}
function agentHtml(agent){if(!agent)return'';const name=window._nodeNames[agent];return name?h(name)+' <span class="t-xs" style="color:var(--z-dim)">('+h(agent)+')</span>':h(agent);}
function timeAgo(ms) {
  const s=Math.floor(Date.now()/1000-ms/1000);
  if(s<0) return 'just now';
  if(s<60) return s+'s ago';
  if(s<3600) return Math.floor(s/60)+'m ago';
  if(s<86400) return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago';
}
function mosColor(m){const s=getComputedStyle(document.documentElement);return m>=40?s.getPropertyValue('--z-ok').trim():m>=30?s.getPropertyValue('--z-warn').trim():s.getPropertyValue('--z-err').trim();}
function themeColor(name){return getComputedStyle(document.documentElement).getPropertyValue('--z-'+name).trim();}

// PCAP generator — Ethernet + IPv4 + UDP + SIP with valid checksums
// Produces files that Wireshark fully dissects as SIP protocol
function buildPcap(messages){
  const buf=[];
  // Global header: magic, v2.4, snaplen=65535, linktype=1 (Ethernet)
  const ghdr=new ArrayBuffer(24);
  const gv=new DataView(ghdr);
  gv.setUint32(0,0xa1b2c3d4,true);gv.setUint16(4,2,true);gv.setUint16(6,4,true);
  gv.setInt32(8,0,true);gv.setUint32(12,0,true);gv.setUint32(16,65535,true);gv.setUint32(20,1,true);
  buf.push(new Uint8Array(ghdr));

  messages.sort((a,b)=>(a.ts_ms||0)-(b.ts_ms||0));
  let ipId=1;

  messages.forEach(m=>{
    if(!m.raw_b64) return;
    const raw=Uint8Array.from(atob(m.raw_b64),c=>c.charCodeAt(0));
    if(!raw.length) return;

    const [srcIp,srcPort]=parseEp(m.src||'0.0.0.0:5060');
    const [dstIp,dstPort]=parseEp(m.dst||'0.0.0.0:5060');
    const srcB=ipBytes(srcIp), dstB=ipBytes(dstIp);

    const udpLen=8+raw.length;
    const ipLen=20+udpLen;
    const ethLen=14+ipLen;
    const pkt=new Uint8Array(ethLen);
    const dv=new DataView(pkt.buffer);

    // Ethernet header (14 bytes) — dummy MACs, EtherType=0x0800 (IPv4)
    pkt[0]=0x00;pkt[1]=0x00;pkt[2]=0x00;pkt[3]=0x00;pkt[4]=0x00;pkt[5]=0x02; // dst MAC
    pkt[6]=0x00;pkt[7]=0x00;pkt[8]=0x00;pkt[9]=0x00;pkt[10]=0x00;pkt[11]=0x01; // src MAC
    dv.setUint16(12,0x0800); // EtherType IPv4

    // IPv4 header (20 bytes) at offset 14
    const ipo=14;
    pkt[ipo]=0x45;          // Version=4, IHL=5
    pkt[ipo+1]=0x00;        // DSCP/ECN
    dv.setUint16(ipo+2,ipLen); // Total length
    dv.setUint16(ipo+4,ipId++); // Identification
    dv.setUint16(ipo+6,0x4000); // Flags: Don't Fragment
    pkt[ipo+8]=64;          // TTL
    pkt[ipo+9]=17;          // Protocol: UDP
    // Checksum at ipo+10 (set after calculation)
    srcB.forEach((b,i)=>{pkt[ipo+12+i]=b;});
    dstB.forEach((b,i)=>{pkt[ipo+16+i]=b;});
    // IP header checksum
    let cksum=0;
    for(let i=0;i<20;i+=2) cksum+=dv.getUint16(ipo+i);
    while(cksum>0xffff) cksum=(cksum&0xffff)+(cksum>>16);
    dv.setUint16(ipo+10,(~cksum)&0xffff);

    // UDP header (8 bytes) at offset 34
    const uo=ipo+20;
    dv.setUint16(uo,srcPort);
    dv.setUint16(uo+2,dstPort);
    dv.setUint16(uo+4,udpLen);
    // UDP checksum (pseudo-header + UDP header + data)
    let usum=0;
    // Pseudo-header: src IP, dst IP, zero, protocol(17), UDP length
    for(let i=0;i<4;i+=2) usum+=dv.getUint16(ipo+12+i); // src IP
    for(let i=0;i<4;i+=2) usum+=dv.getUint16(ipo+16+i); // dst IP
    usum+=17; // protocol
    usum+=udpLen; // UDP length
    // UDP header (without checksum field)
    usum+=srcPort+dstPort+udpLen;
    // Payload
    for(let i=0;i<raw.length-1;i+=2) usum+=(raw[i]<<8)|raw[i+1];
    if(raw.length%2) usum+=(raw[raw.length-1]<<8); // pad odd byte
    while(usum>0xffff) usum=(usum&0xffff)+(usum>>16);
    const udpCk=(~usum)&0xffff;
    dv.setUint16(uo+6,udpCk||0xffff); // 0 means no checksum, use 0xffff

    // SIP payload
    pkt.set(raw,uo+8);

    // PCAP packet header (16 bytes)
    const ts=m.ts_ms||0;
    const phdr=new ArrayBuffer(16);
    const pv=new DataView(phdr);
    pv.setUint32(0,Math.floor(ts/1000),true);   // ts_sec
    pv.setUint32(4,(ts%1000)*1000,true);         // ts_usec
    pv.setUint32(8,ethLen,true);                 // incl_len
    pv.setUint32(12,ethLen,true);                // orig_len
    buf.push(new Uint8Array(phdr));
    buf.push(pkt);
  });
  return new Blob(buf,{type:'application/vnd.tcpdump.pcap'});
}
function parseEp(s){
  // Handle [ipv6]:port and ipv4:port
  if(s.startsWith('[')){const m=s.match(/^\[([^\]]+)\]:(\d+)/);return m?[m[1],parseInt(m[2])]:[s,5060];}
  const i=s.lastIndexOf(':');
  if(i<0) return[s,5060];
  return[s.substring(0,i),parseInt(s.substring(i+1))||5060];
}
function ipBytes(s){
  // IPv4 only for PCAP (IPv6 would need different Ethernet type + 40-byte header)
  return s.split('.').map(x=>parseInt(x)||0).slice(0,4);
}
function downloadBlob(blob,name){const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download=name;a.click();URL.revokeObjectURL(a.href);}
function perSec(c,s){return s>0?(c/s).toFixed(2):'0.00'}
function $(id){return document.getElementById(id)}

// Router
let intervals=[];
function clearIntervals(){intervals.forEach(clearInterval);intervals=[]}
function poll(fn,ms){fn();intervals.push(setInterval(fn,ms))}
const pages={};

function navigate(){
  clearIntervals();
  const raw=location.hash.replace('#','')||'/';
  const page=raw.split('?')[0];
  const params=new URLSearchParams(raw.includes('?')?raw.split('?')[1]:'');
  document.querySelectorAll('.nav-item').forEach(el=>{
    const p=el.dataset.page;
    const match=p&&(('#/'+p==='#'+page)||(p==='overview'&&page==='/'));
    el.classList.toggle('active',!!match);
  });
  (pages[page]||pages['/'])(params);
}
window.addEventListener('hashchange',navigate);

// Status
async function updateStatus(){
  const d=await api('/api/health');
  const el=$('core-status');
  if(d&&d.ok){
    const up=Math.floor(n(d,'uptime_ms')/1000);
    el.innerHTML='<span class="dot dot-ok"></span><span class="c-ok">core up</span><span class="t-xs" style="color:var(--z-dim)">'+up+'s</span>';
  } else {
    el.innerHTML='<span class="dot dot-err"></span><span class="c-err">core down</span>';
  }
}
setInterval(updateStatus,5000);

// KPI card — colorClass is semantic: c-ok, c-warn, c-err, c-muted, or empty for neutral
function kpi(label,value,sub,colorClass){
  const cc=colorClass||'';
  // Map old v-* classes to semantic
  const cls=cc.replace('c-ok','c-ok').replace('c-err','c-err').replace('c-warn','c-warn').replace('c-muted','').replace('c-muted','').replace('c-muted','');
  return '<div class="card p-4"><div class="t-xs" style="color:var(--z-dim)">'+h(label)+'</div><div class="t-hero mono mt-1 '+cls+'">'+value+'</div><div class="t-xs mt-2" style="color:var(--z-sub)">'+h(sub)+'</div></div>';
}

// ===== OVERVIEW =====
pages['/']=function(){
  const m=$('main');
  m.innerHTML='<div class="flex items-center justify-between mb-5"><div><h1 class="t-lg">Overview</h1></div><div><select id="ov-agent" onchange="window._ovAgent=this.value" class="t-sm"><option value="">All servers</option></select></div></div>'+
    '<div id="ov-hero"></div>'+
    '<div class="grid grid-cols-2 lg:grid-cols-4 gap-3 mt-3" id="ov-stats"></div>'+
    '<div class="grid lg:grid-cols-[2fr_1fr] gap-4 mt-5" id="ov-charts" style="display:none"><div class="card p-4"><div class="sec-label">Traffic over time</div><div style="aspect-ratio:3/1;min-height:120px"><canvas id="ov-chart-traffic"></canvas></div></div>'+
    '<div class="card p-4"><div class="sec-label">Response distribution</div><div style="aspect-ratio:1/1;max-height:200px;margin:0 auto"><canvas id="ov-chart-codes"></canvas></div></div></div>'+
    '<div class="grid lg:grid-cols-[1fr_1fr] gap-4 mt-5"><div id="ov-nodes"></div><div id="ov-feed"></div></div>';
  window._ovAgent='';
  window._ovHistory=window._ovHistory||{labels:[],total:[],invites:[],r2xx:[],r4xx:[],r5xx:[]};
  window._ovCharts={};

  async function refreshOverview(){
    const since=Date.now()-300000;
    let feedUrl='/api/messages?limit=15&since_ms='+since+'&method=INVITE';
    if(window._ovAgent) feedUrl+='&agent='+window._ovAgent;
    const [rt,nodes,msgs]=await Promise.all([api('/api/realtime?window=1'),api('/api/nodes'),api(feedUrl)]);
    if(rt){
      const fails=n(rt,'resp_4xx')+n(rt,'resp_5xx');
      const asr=n(rt,'asr');
      const cps=perSec(n(rt,'invites'),60);

      // Hero — 3 primary metrics only, large
      $('ov-hero').innerHTML='<div class="grid grid-cols-3 gap-4">'+
        '<div class="card p-4"><div class="t-xs" style="color:var(--z-dim)">Concurrent calls</div><div class="t-hero mono mt-2">'+fmt(n(rt,'active_calls'))+'</div></div>'+
        '<div class="card p-4"><div class="t-xs" style="color:var(--z-dim)">Calls per second</div><div class="t-hero mono mt-2">'+cps+'</div></div>'+
        '<div class="card p-4"><div class="t-xs" style="color:var(--z-dim)">Answer rate</div><div class="t-hero mono mt-2 '+asrColor(asr)+'">'+asr+'%</div></div>'+
        '</div>';

      // Secondary — 4 compact, semantic colors only
      $('ov-stats').innerHTML=
        kpi('Attempts',fmt(n(rt,'invites')),'last 1 min','')+
        kpi('Answered',fmt(n(rt,'answered_calls')),'completed','c-ok')+
        kpi('Failed',fmt(fails),'4xx/5xx',errColor(fails))+
        kpi('ACD',n(rt,'acd_seconds')+'s','avg call duration','');

      // Update charts
      const hist=window._ovHistory;
      const now=new Date().toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
      hist.labels.push(now);
      hist.total.push(n(rt,'total'));
      hist.invites.push(n(rt,'invites'));
      hist.r2xx.push(n(rt,'resp_2xx'));
      hist.r4xx.push(n(rt,'resp_4xx'));
      hist.r5xx.push(n(rt,'resp_5xx'));
      // Keep last 60 points
      if(hist.labels.length>60){Object.keys(hist).forEach(k=>{hist[k]=hist[k].slice(-60);});}

      // Charts — appear after 2+ data points
      if(hist.labels.length>=2){
        const chartsEl=$('ov-charts');
        if(chartsEl) chartsEl.style.display='';

        const cOpts={responsive:true,maintainAspectRatio:false,animation:{duration:200},plugins:{legend:{position:'top',align:'end',labels:{boxWidth:6,padding:10,font:{size:11,family:'Inter'},color:getComputedStyle(document.documentElement).getPropertyValue('--z-dim')}}},scales:{x:{ticks:{maxTicksToLimit:8,font:{size:10},color:getComputedStyle(document.documentElement).getPropertyValue('--z-dim')},grid:{display:false}},y:{beginAtZero:true,ticks:{font:{size:10},color:getComputedStyle(document.documentElement).getPropertyValue('--z-dim')},grid:{color:getComputedStyle(document.documentElement).getPropertyValue('--z-line')}}}};

        const tc=$('ov-chart-traffic');
        if(tc){
          const okC=getComputedStyle(document.documentElement).getPropertyValue('--z-ok').trim();
          const dimC=getComputedStyle(document.documentElement).getPropertyValue('--z-dim').trim();
          if(window._ovCharts.traffic){window._ovCharts.traffic.data.labels=hist.labels;window._ovCharts.traffic.data.datasets[0].data=hist.total;window._ovCharts.traffic.data.datasets[1].data=hist.invites;window._ovCharts.traffic.update();}
          else{window._ovCharts.traffic=new Chart(tc,{type:'line',data:{labels:hist.labels,datasets:[{label:'Messages',data:hist.total,borderColor:dimC,backgroundColor:'transparent',borderWidth:1.5,pointRadius:0,fill:false,tension:0.3},{label:'Calls',data:hist.invites,borderColor:okC,backgroundColor:okC+'15',borderWidth:1.5,pointRadius:0,fill:true,tension:0.3}]},options:cOpts});}
        }

        const cc=$('ov-chart-codes');
        if(cc){
          const codeData=[n(rt,'resp_2xx'),n(rt,'resp_4xx'),n(rt,'resp_5xx')];
          const okC=getComputedStyle(document.documentElement).getPropertyValue('--z-ok').trim();
          const warnC=getComputedStyle(document.documentElement).getPropertyValue('--z-warn').trim();
          const errC=getComputedStyle(document.documentElement).getPropertyValue('--z-err').trim();
          if(window._ovCharts.codes){window._ovCharts.codes.data.datasets[0].data=codeData;window._ovCharts.codes.update();}
          else{window._ovCharts.codes=new Chart(cc,{type:'doughnut',data:{labels:['Success','Client err','Server err'],datasets:[{data:codeData,backgroundColor:[okC,warnC,errC],borderWidth:0,hoverOffset:4}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:200},cutout:'60%',plugins:{legend:{position:'bottom',labels:{boxWidth:6,padding:10,font:{size:11,family:'Inter'},color:getComputedStyle(document.documentElement).getPropertyValue('--z-dim')}}}}});}
        }
      }
    }

    // Nodes — full width table
    if(nodes&&nodes.length){
      const sel=$('ov-agent');
      if(sel&&sel.options.length<=1){
        nodes.forEach(nd=>{const o=document.createElement('option');o.value=nd.agent;o.text=agentName(nd.agent);sel.appendChild(o);});
      }
      let rows='';
      nodes.forEach(nd=>{
        const s=nd.status||'red';
        const dot=s==='green'?'dot-green':s==='yellow'?'dot-yellow':'dot-red';
        const total=n(nd,'total');
        rows+='<tr>'+
          '<td><span class="flex items-center gap-2"><span class="w-2 h-2 rounded-full '+dot+'"></span>'+agentHtml(nd.agent)+'</span></td>'+
          '<td class="mono">'+total.toLocaleString()+'</td>'+
          '<td class="mono c-muted">'+n(nd,'active_calls').toLocaleString()+'</td>'+
          '<td class="mono">'+n(nd,'calls').toLocaleString()+'</td>'+
          '<td class="mono'+(n(nd,'errors')>0?' c-err':'')+'">'+(n(nd,'errors')>0?n(nd,'errors'):'\u2014')+'</td>'+
          '<td style="color:var(--z-sub)">'+n(nd,'age_sec')+'s</td></tr>';
      });
      $('ov-nodes').innerHTML='<div class="card"><div class="p-3 px-4" style="border-bottom:1px solid var(--z-line)"><span class="sec-label" style="margin:0">Servers</span></div><table><thead><tr><th>Node</th><th>5 min</th><th>Active</th><th>Calls</th><th>Errors</th><th>Seen</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }

    // Live feed
    if(msgs&&msgs.length){
      let rows='';
      msgs.forEach(m=>{
        rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(m.call_id||'')+'\'">'+
          '<td class="mono c-accent truncate max-w-[220px]">'+h(m.call_id||'')+'</td>'+
          '<td class="mono">'+h(m.src||'')+'</td>'+
          '<td class="mono">'+h(m.dst||'')+'</td>'+
          '<td>'+agentHtml(m.agent)+'</td>'+
          '<td style="color:var(--z-sub)">'+(m.ts_ms?timeAgo(m.ts_ms):'')+'</td></tr>';
      });
      $('ov-feed').innerHTML='<div class="card"><div class="p-3 px-4" style="border-bottom:1px solid var(--z-line)"><span class="sec-label" style="margin:0">Recent calls</span></div><table><thead><tr><th>Call-ID</th><th>Source</th><th>Destination</th><th>Server</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }
  }
  poll(refreshOverview,5000);
};

// ===== CALLS =====
pages['/calls']=function(){
  $('main').innerHTML='<h1 class="t-lg">Calls</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">Active call state tracking. Filter by IP, caller, or callee.</p>'+
    '<div class="flex gap-2 mb-4 flex-wrap">'+
    '<input id="cl-src" placeholder="Source IP" class="w-36">'+
    '<input id="cl-dst" placeholder="Dest IP" class="w-36">'+
    '<input id="cl-from" placeholder="From / Caller" class="w-36">'+
    '<input id="cl-to" placeholder="To / Callee" class="w-36">'+
    '<input id="cl-code" placeholder="Status code" class="w-28">'+
    '<select id="cl-state" class="w-28"><option value="">All states</option><option value="open">Ringing</option><option value="answered">Answered</option><option value="ended">Ended</option></select>'+
    '<button onclick="searchCalls()" class="rounded-md px-3 py-1.5 sec-label" style="margin:0 cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Search</button>'+
    '<button onclick="document.querySelectorAll(\'#cl-src,#cl-dst,#cl-from,#cl-to,#cl-code\').forEach(e=>e.value=\'\');$(\'cl-state\').value=\'\';searchCalls()" class="rounded-lg px-3 py-1.5 sec-label" style="margin:0 cursor-pointer" style="border:1px solid var(--z-line);color:var(--z-sub)">Clear</button>'+
    '<a href="/api/export/csv?limit=500" target="_blank" class="rounded-lg px-3 py-1.5 sec-label" style="margin:0 cursor-pointer" style="border:1px solid var(--z-line);color:var(--z-sub);text-decoration:none">CSV</a></div>'+
    '<div class="flex gap-2 mb-5" style="border-bottom:1px solid var(--z-line);padding-bottom:1px">'+
    '<button onclick="$(\'cl-view-calls\').style.display=\'\';$(\'cl-view-carrier\').style.display=\'none\';this.style.borderBottom=\'2px solid var(--z-ink)\';this.nextElementSibling.style.borderBottom=\'none\'" class="px-3 py-2 sec-label" style="margin:0 cursor-pointer" style="border-bottom:2px solid var(--z-ink)">Calls</button>'+
    '<button onclick="$(\'cl-view-calls\').style.display=\'none\';$(\'cl-view-carrier\').style.display=\'\';this.style.borderBottom=\'2px solid var(--z-ink)\';this.previousElementSibling.style.borderBottom=\'none\';if(!window._carrierLoaded){window._carrierLoaded=true;loadCarriers();}" class="px-3 py-2 sec-label" style="margin:0 cursor-pointer" style="color:var(--z-sub)">Carrier Analysis</button></div>'+
    '<div id="cl-view-calls"><div id="cl-table"></div></div>'+
    '<div id="cl-view-carrier" style="display:none"><div class="flex items-center gap-3 mb-4">'+
    '<select id="ca-agent" class="t-xs"><option value="">All servers</option></select>'+
    '<button onclick="loadCarriers()" class="rounded-md px-3 py-1.5 sec-label" style="margin:0 cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Analyze</button></div>'+
    '<div id="ca-results"></div></div>';
  window.searchCalls=async function(){
    let q='?limit=50';
    const src=$('cl-src').value,dst=$('cl-dst').value,from=$('cl-from').value,to=$('cl-to').value,state=$('cl-state').value,code=$('cl-code').value;
    if(src)q+='&src='+encodeURIComponent(src);
    if(dst)q+='&dst='+encodeURIComponent(dst);
    if(from)q+='&from_number='+encodeURIComponent(from);
    if(to)q+='&to_number='+encodeURIComponent(to);
    if(state)q+='&state='+encodeURIComponent(state);
    if(code)q+='&limit=200';
    $('cl-table').innerHTML='<div class="card p-4 t-sm" style="color:var(--z-sub)">Loading...</div>';
    let calls=await api('/api/calls/active'+q);
    if(code&&calls){const c=parseInt(code);calls=calls.filter(x=>{const s=x.status||x.last_status||0;return c<10?String(s).startsWith(String(c)):s===c;});}
    if(!calls||!calls.length){$('cl-table').innerHTML='<div class="card p-4 t-sm" style="color:var(--z-sub)">No calls found.</div>';return;}
    let rows='';
    calls.forEach(c=>{
      const st=n(c,'answered')?'<span class="c-ok">answered</span>':n(c,'open')?'<span class="c-warn">ringing</span>':'<span class="c-err">ended</span>';
      const sc=c.status||c.last_status||0;
      const scc=sc>=500?'c-err':sc>=400?'c-warn':sc>=200?'c-ok':'';
      rows+='<tr class="cursor-pointer hover:opacity-80" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(c.call_id||'')+'\'"><td class="mono c-id truncate max-w-[180px]">'+h(c.call_id||'')+'</td><td>'+agentHtml(c.agent)+'</td><td class="mono">'+h(c.src||'')+'</td><td class="mono">'+h(c.dst||'')+'</td><td>'+h(c.from_h||'')+'</td><td>'+h(c.to_h||'')+'</td><td class="mono '+scc+'">'+(sc||'')+'</td><td>'+st+'</td><td class="text-[var(--z-muted)]">'+(c.first_ts_ms?timeAgo(c.first_ts_ms):'')+'</td></tr>';
    });
    $('cl-table').innerHTML='<div class="card"><table><thead><tr><th>Call-ID</th><th>Agent</th><th>Source</th><th>Destination</th><th>From</th><th>To</th><th>Code</th><th>State</th><th>Started</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  };
  // Auto-search on enter key
  ['cl-src','cl-dst','cl-from','cl-to','cl-code'].forEach(id=>{
    $(id).addEventListener('keydown',e=>{if(e.key==='Enter')searchCalls();});
  });
  searchCalls();
  intervals.push(setInterval(searchCalls,5000));

  // Populate carrier analysis agent dropdown
  api('/api/nodes').then(nodes=>{
    if(!nodes)return;
    const sel=$('ca-agent');
    nodes.forEach(nd=>{const o=document.createElement('option');o.value=nd.agent;o.text=agentName(nd.agent);sel.appendChild(o);});
  });

  window.loadCarriers=async function(){
    const agent=$('ca-agent').value;
    $('ca-results').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-sub)">Analyzing traffic'+(agent?' for '+agentName(agent):'')+' ...</div>';
    let url='/api/messages?limit=500';
    if(agent) url+='&agent='+encodeURIComponent(agent);
    const msgs=await api(url);
    if(!msgs||!msgs.length){$('ca-results').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-sub)">No data.</div>';return;}

    // Group by call_id, track per-call state
    const calls={};
    msgs.forEach(m=>{
      const cid=m.call_id;if(!cid)return;
      if(!calls[cid])calls[cid]={dst:'',invite:false,answered:false,failed:false,failCode:0,inviteTs:0,byeTs:0};
      const meth=m.method||'';
      const st=m.status||0;
      if(meth==='INVITE'&&m.kind==='request'){
        calls[cid].invite=true;
        calls[cid].dst=(m.dst||'').split(':')[0];
        if(!calls[cid].inviteTs)calls[cid].inviteTs=m.ts_ms||0;
      }
      if(meth.includes('INVITE')&&st>=200&&st<300)calls[cid].answered=true;
      if(meth.includes('INVITE')&&st>=400){calls[cid].failed=true;calls[cid].failCode=st;}
      if(meth==='BYE'||meth.includes('BYE'))calls[cid].byeTs=Math.max(calls[cid].byeTs,m.ts_ms||0);
    });

    // Aggregate per destination
    const dsts={};
    Object.values(calls).forEach(c=>{
      if(!c.invite||!c.dst)return;
      if(!dsts[c.dst])dsts[c.dst]={attempts:0,answered:0,failed:0,durations:[],codes:{}};
      const d=dsts[c.dst];
      d.attempts++;
      if(c.answered){
        d.answered++;
        if(c.byeTs&&c.inviteTs){const dur=Math.round((c.byeTs-c.inviteTs)/1000);if(dur>0&&dur<7200)d.durations.push(dur);}
      }
      if(c.failed){d.failed++;d.codes[c.failCode]=(d.codes[c.failCode]||0)+1;}
    });

    // Overall stats
    let totalAttempts=0,totalAnswered=0,totalFailed=0,allDurations=[];
    Object.values(dsts).forEach(d=>{totalAttempts+=d.attempts;totalAnswered+=d.answered;totalFailed+=d.failed;allDurations=allDurations.concat(d.durations);});
    const overallAsr=totalAttempts>0?Math.round(totalAnswered*100/totalAttempts):0;
    const overallAcd=allDurations.length>0?Math.round(allDurations.reduce((a,b)=>a+b,0)/allDurations.length):0;
    const serverLabel=agent?agentName(agent):'all servers';

    // Build table sorted by attempts desc
    let rows='';
    Object.entries(dsts).sort((a,b)=>b[1].attempts-a[1].attempts).forEach(([dst,d])=>{
      const asr=d.attempts>0?Math.round(d.answered*100/d.attempts):0;
      const acd=d.durations.length>0?Math.round(d.durations.reduce((a,b)=>a+b,0)/d.durations.length):0;
      const asrColor=asr>=70?'c-ok':asr>=40?'c-warn':'c-err';
      const codes=Object.entries(d.codes).sort((a,b)=>b[1]-a[1]).map(([c,n])=>c+':'+n).join(' ');
      rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ip?addr='+encodeURIComponent(dst)+'\'">'+
        '<td class="mono c-accent">'+h(dst)+'</td>'+
        '<td class="mono">'+d.attempts+'</td>'+
        '<td class="mono c-ok">'+d.answered+'</td>'+
        '<td class="mono '+(d.failed>0?'c-err':'')+'">'+d.failed+'</td>'+
        '<td class="mono '+asrColor+'">'+asr+'%</td>'+
        '<td class="mono">'+acd+'s</td>'+
        '<td class="mono t-xs" style="color:var(--z-sub)">'+codes+'</td></tr>';
    });

    $('ca-results').innerHTML=
      '<div class="grid grid-cols-4 gap-3 mb-4">'+
      kpi('Overall ASR',overallAsr+'%',totalAnswered+' / '+totalAttempts+' via '+serverLabel,overallAsr>=70?'c-ok':overallAsr>=40?'c-warn':'c-err')+
      kpi('Overall ACD',overallAcd+'s',allDurations.length+' completed calls','c-muted')+
      kpi('Attempts',totalAttempts,'INVITEs sampled','c-muted')+
      kpi('Destinations',Object.keys(dsts).length,'unique carrier IPs','c-muted')+
      '</div>'+
      '<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">Per-Destination Breakdown</div><div class="t-xs mt-1" style="color:var(--z-sub)">ASR and ACD per carrier/destination IP. Click a row for full IP history.</div></div>'+
      '<table><thead><tr><th>Destination</th><th>Attempts</th><th>Answered</th><th>Failed</th><th>ASR</th><th>ACD</th><th>Fail codes</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  };
};

// ===== MESSAGES =====
pages['/messages']=function(params){
  $('main').innerHTML='<h1 class="t-lg">Messages</h1><p class="t-xs mt-0.5 mb-4" style="color:var(--z-sub)">SIP message search with filters and time ranges</p>'+
    '<div class="flex gap-2 mb-2 flex-wrap">'+
    '<input id="m-cid" placeholder="Call-ID (prefix with / for regex)" class="flex-1 min-w-[160px]">'+
    '<input id="m-method" placeholder="Method" class="w-24">'+
    '<input id="m-status" placeholder="Status" class="w-20">'+
    '<input id="m-ip" placeholder="IP address" class="w-32">'+
    '<select id="m-preset" onchange="applyPreset()" class="w-32"><option value="">Quick filters...</option><option value="errors">All Errors</option><option value="403">403 Forbidden</option><option value="404">404 Not Found</option><option value="486">486 Busy</option><option value="487">487 Cancelled</option><option value="500">500 Server Error</option><option value="503">503 Unavailable</option><option value="invite">INVITEs only</option><option value="register">REGISTERs only</option></select></div>'+
    '<div class="flex gap-2 mb-4 flex-wrap items-center">'+
    '<span class="t-xs" style="color:var(--z-dim)">Range:</span>'+
    '<select id="m-range" onchange="doSearch()" class="t-xs w-28"><option value="600000">Last 10 min</option><option value="1800000">Last 30 min</option><option value="3600000">Last 1 hour</option><option value="14400000">Last 4 hours</option><option value="86400000">Last 24 hours</option><option value="0">All time</option></select>'+
    '<button onclick="doSearch()" class="rounded-md px-3 py-1.5 sec-label" style="margin:0 cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Search</button>'+
    '<button onclick="saveCurrentSearch()" class="rounded-md px-3 py-1.5 t-xs font-medium cursor-pointer" style="border:1px solid var(--z-line);color:var(--z-sub)">Save</button>'+
    '<span id="m-count" class="t-xs mono" style="color:var(--z-dim)"></span></div>'+
    '<div id="m-saved"></div>'+
    '<div id="m-table"><div class="card p-4 text-xs" style="color:var(--z-sub)">Loading recent messages...</div></div>';
  window.applyPreset=function(){
    const v=$('m-preset').value;
    if(v==='errors'){$('m-status').value='';$('m-method').value='';} // handled specially
    else if(v==='invite'){$('m-method').value='INVITE';$('m-status').value='';}
    else if(v==='register'){$('m-method').value='REGISTER';$('m-status').value='';}
    else if(v){$('m-status').value=v;$('m-method').value='';}
    doSearch();
  };
  window.doSearch=async function(){
    const cid=$('m-cid').value,method=$('m-method').value,ip=$('m-ip').value,status=$('m-status').value;
    const preset=$('m-preset').value;
    const rangeMs=parseInt($('m-range').value)||600000;
    const since=rangeMs>0?Date.now()-rangeMs:0;
    let q='?limit=200';
    if(since>0) q+='&since_ms='+since;
    if(cid)q+='&call_id='+cid;
    if(method)q+='&method='+encodeURIComponent(method);
    if(ip)q+='&ip='+encodeURIComponent(ip);
    if(status)q+='&status='+encodeURIComponent(status);
    $('m-table').innerHTML='<div class="card p-4 t-sm" style="color:var(--z-sub)">Searching...</div>';
    let msgs=await api('/api/messages'+q);
    // Client-side filter for "all errors" preset (status >= 400)
    if(preset==='errors'&&msgs){msgs=msgs.filter(m=>m.status>=400);}
    if(!msgs||!msgs.length){$('m-table').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-sub)">No messages found.</div>';$('m-count').textContent='0 results';return;}
    $('m-count').textContent=msgs.length+' results';
    let rows='';
    msgs.forEach(m=>{
      const st=m.status||0;
      const sc=st>=500?'c-err':st>=400?'c-warn':st>=300?'c-muted':st>=200?'c-ok':'';
      const mc=m.method&&m.method.includes('INVITE')?'c-err':'';
      rows+='<tr class="cursor-pointer hover:opacity-80" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(m.call_id||'')+'\'"><td class="mono '+mc+'">'+h(m.method||'')+'</td><td class="mono '+sc+'">'+(st||'')+'</td><td class="mono c-id truncate max-w-[180px]">'+h(m.call_id||'')+'</td><td class="mono">'+h(m.src||'')+'</td><td class="mono">'+h(m.dst||'')+'</td><td class="text-[var(--z-muted)]">'+agentHtml(m.agent)+'</td><td class="text-[var(--z-muted)]">'+(m.ts_ms?timeAgo(m.ts_ms):'')+'</td></tr>';
    });
    $('m-table').innerHTML='<div class="card"><table><thead><tr><th>Method</th><th>Status</th><th>Call-ID</th><th>Source</th><th>Destination</th><th>Agent</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  };

  // Saved searches
  async function loadSavedSearches(){
    const searches=await fetch('/web/searches',{headers:headers()}).then(r=>r.ok?r.json():[]);
    if(!searches||!searches.length){$('m-saved').innerHTML='';return;}
    let links='';
    searches.forEach(s=>{
      const p=s.params||{};
      links+='<div class="flex items-center gap-1"><button onclick="applySaved('+JSON.stringify(JSON.stringify(p)).replace(/"/g,'&quot;')+')" class="t-xs c-accent hover:underline cursor-pointer">'+h(s.name)+'</button>'+
        '<button onclick="deleteSaved('+s.id+')" class="t-xs cursor-pointer" style="color:var(--z-dim)">&times;</button></div>';
    });
    $('m-saved').innerHTML='<div class="flex flex-wrap gap-2 items-center mb-3"><span class="t-xs" style="color:var(--z-dim)">Saved:</span>'+links+'</div>';
  }
  window.applySaved=function(paramsJSON){
    const p=JSON.parse(paramsJSON);
    $('m-cid').value=p.call_id||'';$('m-method').value=p.method||'';$('m-status').value=p.status||'';$('m-ip').value=p.ip||'';
    doSearch();
  };
  window.saveCurrentSearch=async function(){
    const name=prompt('Name this search:');
    if(!name) return;
    const params={call_id:$('m-cid').value,method:$('m-method').value,status:$('m-status').value,ip:$('m-ip').value};
    await fetch('/web/searches',{method:'POST',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify({name,params})});
    loadSavedSearches();
  };
  window.deleteSaved=async function(id){
    await fetch('/web/searches',{method:'DELETE',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify({id})});
    loadSavedSearches();
  };
  loadSavedSearches();
  doSearch();
};

// ===== LADDER (Call Detail) =====
pages['/ladder']=async function(params){
  const cid=decodeURIComponent(params.get('call_id')||'');
  const m=$('main');
  m.innerHTML='<div class="flex items-center gap-3 mb-5"><a href="#/calls" style="color:var(--z-sub)" class="t-sm hover:underline">&larr; Back</a><div><h1 class="t-lg">Call Detail</h1><p class="t-xs mono mt-0.5 break-all" style="color:var(--z-sub)">'+h(cid)+'</p></div></div><div id="ld-content"><div class="card p-4 text-xs" style="color:var(--z-sub)">Loading call data...</div></div>';

  const msgs=await api('/api/messages?limit=500&call_id='+encodeURIComponent(cid));
  if(!msgs||!msgs.length){$('ld-content').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-sub)">No messages found for this call.</div>';return;}
  msgs.sort((a,b)=>(a.ts_ms||0)-(b.ts_ms||0));

  const eps=[...new Set(msgs.flatMap(m=>[m.src,m.dst].filter(Boolean)))];
  const epCount=eps.length;
  window._ladderMsgs=msgs;

  // ---- Call Summary ----
  const firstMsg=msgs[0]||{};
  const lastMsg=msgs[msgs.length-1]||{};
  const durationMs=(lastMsg.ts_ms||0)-(firstMsg.ts_ms||0);
  const durationSec=(durationMs/1000).toFixed(1);
  const hasAnswer=msgs.some(m=>m.method&&m.method.includes('INVITE')&&m.status>=200&&m.status<300);
  const hasBye=msgs.some(m=>m.method&&(m.method.includes('BYE')));
  const has4xx=msgs.find(m=>m.status>=400);
  const finalStatus=hasAnswer?(hasBye?'Completed':'In Progress'):(has4xx?'Failed ('+has4xx.status+')':'Ringing');
  const statusColor=finalStatus.startsWith('Completed')?'c-ok':finalStatus.startsWith('Failed')?'c-err':'c-warn';
  const startTime=firstMsg.ts_ms?new Date(firstMsg.ts_ms):'';
  const startStr=startTime?startTime.toLocaleString():'';

  // Count request/response
  const reqCount=msgs.filter(m=>m.kind==='request').length;
  const respCount=msgs.filter(m=>m.kind==='response').length;

  let infoHtml='<div class="card p-4 mb-5"><div class="flex items-center justify-between mb-4"><div class="sec-label" style="margin:0">Call Summary</div><div class="flex gap-2">'+
    '<button onclick="downloadBlob(buildPcap(window._ladderMsgs),\''+h(cid).substring(0,20)+'.pcap\')" class="rounded-md px-3 py-1.5 t-xs font-medium cursor-pointer flex items-center gap-1.5" style="border:1px solid var(--z-line);color:var(--z-sub)"><svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>PCAP</button>'+
    '<button onclick="exportJSON()" class="rounded-md px-3 py-1.5 t-xs font-medium cursor-pointer flex items-center gap-1.5" style="border:1px solid var(--z-line);color:var(--z-sub)"><svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>JSON</button>'+
    '<button onclick="navigator.clipboard.writeText(window.location.href)" class="rounded-md px-3 py-1.5 t-xs font-medium cursor-pointer flex items-center gap-1.5" style="border:1px solid var(--z-line);color:var(--z-sub)"><svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>Copy link</button></div></div>'+
    '<div class="grid grid-cols-2 xl:grid-cols-4 gap-4 t-xsmb-3">'+
    '<div><div class="t-xs" style="color:var(--z-dim)">Status</div><div class="font-semibold mt-0.5 '+statusColor+'">'+finalStatus+'</div></div>'+
    '<div><div class="t-xs" style="color:var(--z-dim)">Duration</div><div class="mono font-semibold mt-0.5">'+durationSec+'s</div></div>'+
    '<div><div class="t-xs" style="color:var(--z-dim)">Messages</div><div class="mono mt-0.5">'+msgs.length+' <span style="color:var(--z-dim)">('+reqCount+' req, '+respCount+' resp)</span></div></div>'+
    '<div><div class="t-xs" style="color:var(--z-dim)">Server</div><div class="mt-0.5">'+agentHtml(firstMsg.agent)+'</div></div>'+
    '</div>'+
    '<div class="grid grid-cols-1 xl:grid-cols-2 gap-3 t-xspt-3" style="border-top:1px solid var(--z-line)">'+
    '<div class="grid grid-cols-[60px_1fr] gap-1">'+
    '<span style="color:var(--z-dim)">From</span><span class="mono break-all">'+h(firstMsg.from||firstMsg.from_h||'')+'</span>'+
    '<span style="color:var(--z-dim)">To</span><span class="mono break-all">'+h(firstMsg.to||firstMsg.to_h||'')+'</span></div>'+
    '<div class="grid grid-cols-[60px_1fr] gap-1">'+
    '<span style="color:var(--z-dim)">Started</span><span class="mono">'+h(startStr)+'</span>'+
    '<span style="color:var(--z-dim)">Endpoints</span><span class="mono">'+epCount+' ('+eps.map(e=>h(e)).join(', ')+')</span></div>'+
    '</div></div>';

  window.exportJSON=function(){
    downloadBlob(new Blob([JSON.stringify(window._ladderMsgs,null,2)],{type:'application/json'}),cid.substring(0,20)+'.json');
  };

  // ---- Interactive SVG SIP Ladder ----
  const colW=200;const rowH=36;const pad=70;const arrowPad=24;
  const svgW=epCount*colW+pad*2+90;
  const svgH=msgs.length*rowH+90;
  const t0=msgs[0]?msgs[0].ts_ms:0;

  let svg='<svg xmlns="http://www.w3.org/2000/svg" width="'+svgW+'" height="'+svgH+'" class="block" style="font-family:ui-monospace,monospace">';

  // Defs — arrowheads for each color
  const arrows={r:themeColor('sub'),g:themeColor('ok'),p:'#c084fc',y:themeColor('warn'),e:themeColor('err'),b:themeColor('sub')};
  svg+='<defs>';
  Object.entries(arrows).forEach(([id,c])=>{
    svg+='<marker id="ah-'+id+'" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto"><path d="M0,0.5 L7,3 L0,5.5" fill="'+c+'" stroke="none"/></marker>';
  });
  // Hover filter
  svg+='<filter id="glow"><feGaussianBlur stdDeviation="2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>';
  svg+='</defs>';

  // Endpoint columns — headers with IP:port
  eps.forEach((ep,i)=>{
    const x=pad+i*colW+colW/2;
    svg+='<rect x="'+(x-70)+'" y="6" width="140" height="28" rx="6" fill="var(--z-card)" stroke="var(--z-line)" stroke-width="1"/>';
    const label=ep.length>20?ep.split(':')[0]:''+ep;
    svg+='<text x="'+x+'" y="24" text-anchor="middle" fill="var(--z-ink)" font-size="10" font-weight="500">'+h(label)+'</text>';
    // Vertical lifeline
    svg+='<line x1="'+x+'" y1="38" x2="'+x+'" y2="'+(svgH-10)+'" stroke="var(--z-line)" stroke-width="1" stroke-dasharray="3,5" opacity="0.6"/>';
  });

  // Message arrows — interactive with hover highlight
  msgs.forEach((msg,i)=>{
    const srcIdx=eps.indexOf(msg.src);
    const dstIdx=eps.indexOf(msg.dst);
    if(srcIdx<0||dstIdx<0) return;
    const y=54+i*rowH;
    const x1=pad+srcIdx*colW+colW/2;
    const x2=pad+dstIdx*colW+colW/2;
    const method=msg.method||'';
    const status=msg.status||0;
    const label=status>0?status+' '+method.replace(/^\d+ /,''):method;
    const isErr=status>=400;
    const isInv=method==='INVITE';
    const is1xx=status>=100&&status<200;
    const is2xx=status>=200&&status<300;
    const is3xx=status>=300&&status<400;
    const isBye=method.includes('BYE');
    const isCancel=method.includes('CANCEL');
    const color=isErr?themeColor('err'):isInv?'#c084fc':isBye||isCancel?themeColor('warn'):is2xx?themeColor('ok'):is1xx?themeColor('dim'):themeColor('sub');
    const mid=isErr?'ah-e':isInv?'ah-p':isBye||isCancel?'ah-y':is2xx?'ah-g':is3xx?'ah-b':'ah-r';
    const goRight=x2>x1;
    const lx1=x1+(goRight?arrowPad:-arrowPad);
    const lx2=x2+(goRight?-arrowPad:arrowPad);
    const labX=(x1+x2)/2;
    const delta=msg.ts_ms-t0;
    const ts=delta<1000?'+'+delta+'ms':'+'+(delta/1000).toFixed(1)+'s';
    const lineStyle=is1xx?'stroke-dasharray="4,3"':'';

    // Clickable group
    svg+='<g class="ladder-row" onclick="toggleRaw('+i+')" style="cursor:pointer">';
    // Invisible wide hit area
    svg+='<rect x="0" y="'+(y-rowH/2+2)+'" width="'+svgW+'" height="'+rowH+'" fill="transparent" class="ladder-hit"/>';
    // Arrow line
    svg+='<line x1="'+lx1+'" y1="'+y+'" x2="'+lx2+'" y2="'+y+'" stroke="'+color+'" stroke-width="1.5" marker-end="url(#'+mid+')" '+lineStyle+'/>';
    // Label above arrow
    svg+='<text x="'+labX+'" y="'+(y-6)+'" text-anchor="middle" fill="'+color+'" font-size="10" font-weight="'+(isInv||is2xx||isErr?'600':'400')+'">'+h(label)+'</text>';
    // Timestamp right side
    svg+='<text x="'+(svgW-12)+'" y="'+(y+3)+'" text-anchor="end" fill="var(--z-dim)" font-size="9">'+ts+'</text>';
    // Sequence number left side
    svg+='<text x="12" y="'+(y+3)+'" fill="var(--z-dim)" font-size="9">'+(i+1)+'</text>';
    svg+='</g>';
  });
  svg+='</svg>';

  // CSS for hover interaction
  const ladderCSS='<style>.ladder-row:hover .ladder-hit{fill:var(--z-hover)}.ladder-row:hover line{stroke-width:2.5!important}.ladder-row:hover text{font-weight:600!important}</style>';

  let ladderHtml='<div class="card mb-5"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="flex items-center justify-between"><div><div class="sec-label" style="margin:0">SIP Ladder</div><div class="t-xs mt-1" style="color:var(--z-sub)">'+msgs.length+' messages between '+epCount+' endpoints</div></div>'+
    '<div class="flex gap-3 t-xs" style="color:var(--z-dim)"><span><span style="color:#c084fc">━</span> INVITE</span><span class="c-ok">━ 2xx</span><span class="c-warn">━ BYE</span><span class="c-err">━ Error</span><span>╌ 1xx</span></div></div></div>'+
    ladderCSS+'<div class="overflow-x-auto" style="background:var(--z-bg)">'+svg+'</div></div>';

  // ---- Message detail panel (shown on click) ----
  let detailHtml='<div id="msg-detail" class="card mb-5" style="display:none"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="flex items-center justify-between"><div class="sec-label" style="margin:0">Message Detail</div><button onclick="$(\'msg-detail\').style.display=\'none\'" class="t-xs cursor-pointer" style="color:var(--z-dim)">&times; close</button></div></div><div id="msg-detail-content" class="p-4"></div></div>';

  // ---- Message list ----
  let msgRows='';
  msgs.forEach((msg,i)=>{
    const method=msg.method||'';
    const status=msg.status||0;
    const label=status>0?status+' '+method.replace(/^\d+ /,''):method;
    const isInv=method==='INVITE';
    const mc=isInv?'c-invite':status>=400?'c-err':status>=200&&status<300?'c-ok':'';
    const delta=msg.ts_ms-t0;
    const ts=delta<1000?'+'+delta+'ms':'+'+(delta/1000).toFixed(1)+'s';
    msgRows+='<tr class="cursor-pointer" onclick="showMsgDetail('+i+')"><td class="t-xs" style="color:var(--z-dim)">'+(i+1)+'</td><td class="mono '+mc+'">'+h(label)+'</td><td class="mono t-xs">'+h(msg.src||'')+'</td><td style="color:var(--z-dim)">→</td><td class="mono t-xs">'+h(msg.dst||'')+'</td><td class="mono t-xs" style="color:var(--z-dim)">'+ts+'</td><td style="color:var(--z-sub)">'+(msg.ts_ms?new Date(msg.ts_ms).toLocaleTimeString():'')+'</td></tr>';
  });

  window.showMsgDetail=function(i){
    const msg=window._ladderMsgs[i];if(!msg)return;
    const method=msg.method||'';const status=msg.status||0;
    const label=status>0?status+' '+method.replace(/^\d+ /,''):method;
    const raw=msg.raw_b64?atob(msg.raw_b64):'(no raw payload)';
    // Parse headers from raw
    const headerEnd=raw.indexOf('\r\n\r\n')>0?raw.indexOf('\r\n\r\n'):raw.indexOf('\n\n');
    const headers=headerEnd>0?raw.substring(0,headerEnd):raw;
    const body=headerEnd>0?raw.substring(headerEnd+4).trim():'';

    let detail='<div class="grid xl:grid-cols-[1fr_1fr] gap-4">';
    // Left: metadata
    detail+='<div><div class="grid grid-cols-[80px_1fr] gap-y-1.5 text-xs">';
    [['Message',label],['Direction',h(msg.src)+' → '+h(msg.dst)],['Transport',msg.transport],['Agent',agentName(msg.agent)],['Time',msg.ts_ms?new Date(msg.ts_ms).toLocaleString():''],['Size',(msg.size||0)+' bytes'],['CSeq',msg.cseq],['Call-ID',msg.call_id]].forEach(([k,v])=>{
      detail+='<div style="color:var(--z-dim)">'+k+'</div><div class="mono break-all">'+h(v||'')+'</div>';
    });
    detail+='</div>';
    if(body){detail+='<div class="mt-3"><div class="t-xs font-medium mb-1" style="color:var(--z-dim)">Body</div><pre class="mono t-xs p-2 rounded whitespace-pre-wrap" style="background:var(--z-bg);color:var(--z-sub)">'+h(body)+'</pre></div>';}
    detail+='</div>';
    // Right: raw SIP
    detail+='<div><div class="t-xs font-medium mb-1" style="color:var(--z-dim)">Raw SIP</div>'+
      '<pre class="mono t-xs p-3 rounded whitespace-pre-wrap break-all" style="background:var(--z-bg);color:var(--z-sub);max-height:400px;overflow-y:auto;line-height:1.5">'+h(raw)+'</pre></div>';
    detail+='</div>';

    $('msg-detail-content').innerHTML=detail;
    $('msg-detail').style.display='';
    $('msg-detail').scrollIntoView({behavior:'smooth',block:'nearest'});
  };

  window.toggleRaw=window.showMsgDetail;

  let msgsHtml='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">Messages</div><div class="t-xs mt-1" style="color:var(--z-sub)">Click any row to view full SIP headers and payload</div></div><table><thead><tr><th>#</th><th>Message</th><th>From</th><th></th><th>To</th><th>Delta</th><th>Time</th></tr></thead><tbody>'+msgRows+'</tbody></table></div>';

  // ---- QoS / Media panel ----
  const qos=await api('/api/qos?call_id='+encodeURIComponent(cid));
  let qosHtml='';
  if(qos&&qos.length>0){
    const q=qos[0];
    const mos=(n(q,'mos_x10')/10).toFixed(1);
    const mosColor=n(q,'mos_x10')>=40?'c-ok':n(q,'mos_x10')>=30?'c-warn':'c-err';
    qosHtml='<div class="card p-4 mb-5"><div class="sec-label" style="margin:0 mb-3">Call Quality (RTCP)</div>'+
      '<div class="grid grid-cols-2 xl:grid-cols-5 gap-3">'+
      kpi('MOS',mos,'voice quality',mosColor)+
      kpi('Jitter',n(q,'jitter_ms')+'ms','max jitter','c-muted')+
      kpi('Loss',n(q,'loss_pct')+'%','max packet loss',n(q,'loss_pct')>2?'c-err':'c-ok')+
      kpi('R-Factor',n(q,'r_factor'),'ITU-T G.107','c-muted')+
      kpi('Codec',q.codec||'—','media codec','c-muted')+
      '</div></div>';
  }

  // ---- SDP / Media info from messages ----
  let mediaHtml='';
  const sdpMsg=msgs.find(m=>{
    if(!m.raw_b64)return false;
    try{const r=atob(m.raw_b64);return r.includes('m=audio');}catch(e){return false;}
  });
  if(sdpMsg){
    try{
      const raw=atob(sdpMsg.raw_b64);
      const codecs=[];let mediaPort=0;let srtp=false;
      raw.split('\n').forEach(line=>{
        line=line.trim();
        if(line.startsWith('m=audio ')){const p=line.split(' ');if(p[1])mediaPort=parseInt(p[1]);if(line.includes('SAVP'))srtp=true;}
        if(line.startsWith('a=rtpmap:')){const p=line.split(' ');if(p[1])codecs.push(p[1].split('/')[0]);}
        if(line.startsWith('a=crypto:'))srtp=true;
      });
      if(codecs.length||mediaPort){
        mediaHtml='<div class="card p-4 mb-5"><div class="sec-label" style="margin:0 mb-3">Media</div>'+
          '<div class="grid grid-cols-3 gap-4 text-xs">'+
          '<div><span style="color:var(--z-dim)">Codecs:</span> <span class="mono">'+h(codecs.join(', ')||'—')+'</span></div>'+
          '<div><span style="color:var(--z-dim)">Media port:</span> <span class="mono">'+(mediaPort||'—')+'</span></div>'+
          '<div><span style="color:var(--z-dim)">Security:</span> '+(srtp?'<span class="c-ok font-medium">SRTP (encrypted)</span>':'<span style="color:var(--z-sub)">RTP (unencrypted)</span>')+'</div>'+
          '</div></div>';
      }
    }catch(e){}
  }

  // ---- Related calls (B2BUA legs) ----
  let relatedHtml='';
  const related=await api('/api/related?call_id='+encodeURIComponent(cid));
  if(related&&related.length){
    let rRows='';
    related.forEach(r=>{
      rRows+='<a href="#/ladder?call_id='+encodeURIComponent(r.call_id||'')+'" class="flex items-center gap-2 px-4 py-2 t-xshover:underline c-accent mono" style="border-bottom:1px solid var(--z-line)">'+h(r.call_id)+' <span class="t-xs" style="color:var(--z-dim)">('+h(r.reason||'correlated')+')</span></a>';
    });
    relatedHtml='<div class="card mb-5"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">Related Call Legs</div><div class="t-xs mt-1" style="color:var(--z-sub)">B2BUA correlated calls — click to view</div></div>'+rRows+'</div>';
  }

  $('ld-content').innerHTML=infoHtml+qosHtml+mediaHtml+ladderHtml+relatedHtml+detailHtml+msgsHtml;

  // ---- Realtime: only append new messages, never reload ----
  if(finalStatus==='In Progress'||finalStatus==='Ringing'){
    window._ladderKnown=msgs.length;
    const refreshLadder=async()=>{
      const fresh=await api('/api/messages?limit=500&call_id='+encodeURIComponent(cid));
      if(!fresh||fresh.length<=window._ladderKnown)return;
      // Show a non-disruptive badge instead of reloading
      const newCount=fresh.length-window._ladderKnown;
      window._ladderKnown=fresh.length;
      const badge=$('ld-live-badge');
      if(badge) badge.innerHTML='<span class="t-xs c-ok mono">● live · '+fresh.length+' messages</span>';
    };
    // Add live badge to the ladder header
    const ladderHeader=document.querySelector('#ld-content .card .text-xs.font-medium');
    if(ladderHeader){
      ladderHeader.insertAdjacentHTML('afterend',' <span id="ld-live-badge" class="ml-2"><span class="t-xs c-ok mono">● live</span></span>');
    }
    intervals.push(setInterval(refreshLadder,5000));
  }
};

// ===== NOC =====
pages['/noc']=function(){
  $('main').innerHTML='<h1 class="t-lg">NOC</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">Node health and server status. Click a name to rename.</p><div id="noc-t"></div>';
  window.renameNode=async function(agent){
    const cur=window._nodeNames[agent]||'';
    const name=prompt('Display name for '+agent+':',cur);
    if(name===null) return;
    const body={};body[agent]=name;
    await fetch('/web/node-names',{method:'POST',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify(body)});
    window._nodeNames[agent]=name||undefined;
    if(!name) delete window._nodeNames[agent];
  };
  poll(async function(){
    const [nodes,agentIps]=await Promise.all([api('/api/nodes'),api('/api/messages?limit=200')]);
    if(!nodes||!nodes.length){$('noc-t').innerHTML='<div class="card p-4 t-sm" style="color:var(--z-sub)">No nodes reporting.</div>';return;}
    // Build IP map per agent from recent messages
    const ipMap={};
    if(agentIps){agentIps.forEach(m=>{
      const a=m.agent||'';if(!a)return;
      if(!ipMap[a])ipMap[a]=new Set();
      const s=(m.src||'').split(':')[0];if(s)ipMap[a].add(s);
      const d=(m.dst||'').split(':')[0];if(d)ipMap[a].add(d);
    });}
    let rows='';
    nodes.forEach(nd=>{
      const agent=nd.agent||'';
      const s=nd.status||'red';
      const dot=s==='green'?'dot-green':s==='yellow'?'dot-yellow':'dot-red';
      const sl=s==='green'?'healthy':s==='yellow'?'stale':'offline';
      const sc=s==='green'?'var(--z-ok)':s==='yellow'?'var(--z-warn)':'var(--z-err)';
      const displayName=window._nodeNames[agent]||'';
      const nameHtml=displayName
        ?'<span class="font-medium">'+h(displayName)+'</span> <span class="t-xs" style="color:var(--z-sub)">('+h(agent)+')</span>'
        :'<span class="font-medium">'+h(agent)+'</span>';
      const ips=ipMap[agent]?Array.from(ipMap[agent]).sort().join(', '):'';
      rows+='<tr>'+
        '<td><div class="flex items-center gap-2 cursor-pointer" onclick="renameNode(\''+agent+'\')"><span class="w-2 h-2 rounded-full '+dot+' shrink-0"></span><div>'+nameHtml+'</div></div></td>'+
        '<td class="mono t-xs" style="color:var(--z-sub)">'+h(ips)+'</td>'+
        '<td style="color:'+sc+'">'+sl+'</td>'+
        '<td class="mono">'+n(nd,'total')+'</td>'+
        '<td class="mono">'+n(nd,'active_calls')+'</td>'+
        '<td class="mono">'+n(nd,'calls')+'</td>'+
        '<td class="mono">'+(n(nd,'errors')>0?'<span class="c-err">'+n(nd,'errors')+'</span>':n(nd,'errors'))+'</td>'+
        '<td class="text-[var(--z-muted)]">'+n(nd,'age_sec')+'s ago</td></tr>';
    });
    $('noc-t').innerHTML='<div class="card"><table><thead><tr><th>Server</th><th>IPs</th><th>Status</th><th>Total 5m</th><th>Active Calls</th><th>Call IDs</th><th>Errors</th><th>Last Seen</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  },5000);
};

// ===== METRICS =====
pages['/metrics']=function(){
  $('main').innerHTML='<h1 class="t-lg">Metrics</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">System health and ingest performance</p>'+
    '<div class="grid lg:grid-cols-[2fr_1fr] gap-4">'+
    '<div><div id="met-health"></div><div class="card p-4 mt-4"><div class="sec-label">Calls per minute</div><div style="aspect-ratio:3/1;min-height:140px"><canvas id="met-cps-chart"></canvas></div></div></div>'+
    '<div><div id="met-codes"></div><div id="met-hep" class="mt-4"></div></div></div>';

  Promise.all([api('/api/metrics'),api('/api/report/cps?minutes=60'),api('/api/report/response-codes')]).then(([s,cps,codes])=>{
    if(s){
      const upH=Math.floor((s.uptime_ms||0)/3600000);
      const upM=Math.floor(((s.uptime_ms||0)%3600000)/60000);
      $('met-health').innerHTML='<div class="card p-4"><div class="sec-label">Ingest health</div>'+
        '<div class="grid grid-cols-2 lg:grid-cols-4 gap-3">'+
        kpi('Messages',fmt(s.msgs_total||0),'total captured','')+
        kpi('DB writes',fmt(s.db_ok||0),'successful','c-ok')+
        kpi('DB errors',fmt(s.db_err||0),'failed',errColor(s.db_err))+
        kpi('Uptime',upH+'h '+upM+'m','service uptime','')+
        '</div></div>';

      // HEP breakdown — single compact table, not 8 KPI cards
      const hep=[['SIP',s.hep_sip],['RTCP',s.hep_rtcp],['RTP',s.hep_rtp],['RTCP-XR',s.hep_rtcpxr]].filter(([,v])=>v>0);
      const transport=[['UDP',s.hep_udp],['TCP',s.hep_tcp],['TLS',s.hep_tls]].filter(([,v])=>v>0);
      let hepRows='';
      hep.forEach(([l,v])=>{hepRows+='<tr><td>'+l+'</td><td class="mono">'+fmt(v)+'</td></tr>';});
      transport.forEach(([l,v])=>{hepRows+='<tr><td>'+l+'</td><td class="mono">'+fmt(v)+'</td></tr>';});
      $('met-hep').innerHTML='<div class="card"><div class="p-3 px-4" style="border-bottom:1px solid var(--z-line)"><span class="sec-label" style="margin:0">Protocol breakdown</span></div>'+
        '<table><thead><tr><th>Type</th><th>Count</th></tr></thead><tbody>'+hepRows+'</tbody></table>'+
        '<div class="p-3 px-4 t-xs" style="color:var(--z-dim);border-top:1px solid var(--z-line)">Total HEP: '+fmt(s.hep_total||0)+' · Requests: '+fmt(s.requests||0)+' · Responses: '+fmt(s.responses||0)+' · Echoes: '+fmt(s.echoes||0)+'</div></div>';
    }

    // CPS chart — theme-aware
    if(cps&&cps.length>1){
      const dimC=getComputedStyle(document.documentElement).getPropertyValue('--z-dim').trim();
      const okC=getComputedStyle(document.documentElement).getPropertyValue('--z-ok').trim();
      const lineC=getComputedStyle(document.documentElement).getPropertyValue('--z-line').trim();
      const labels=cps.map(c=>{const d=new Date(c.minute*60000);return d.toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit'});});
      new Chart($('met-cps-chart'),{type:'line',data:{labels,datasets:[
        {label:'Messages',data:cps.map(c=>c.total),borderColor:dimC,borderWidth:1.5,pointRadius:0,fill:false,tension:0.3},
        {label:'Calls',data:cps.map(c=>c.invites),borderColor:okC,backgroundColor:okC+'15',borderWidth:1.5,pointRadius:0,fill:true,tension:0.3}
      ]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:0},plugins:{legend:{position:'top',align:'end',labels:{boxWidth:6,padding:10,font:{size:11},color:dimC}}},scales:{x:{ticks:{maxTicksToLimit:10,font:{size:10},color:dimC},grid:{display:false}},y:{beginAtZero:true,ticks:{font:{size:10},color:dimC},grid:{color:lineC}}}}});
    }

    // Response codes — semantic colors
    if(codes&&codes.length){
      const maxC=Math.max(...codes.map(c=>c.count||0))||1;
      let rows='';
      codes.forEach(c=>{
        const st=c.status||0;
        const sc=st>=500?'c-err':st>=400?'c-warn':st>=200?'c-ok':'c-muted';
        rows+='<tr><td class="mono '+sc+'">'+st+'</td><td>'+h(c.reason||'')+'</td><td class="mono">'+fmt(c.count)+'</td>'+
          '<td><div style="width:100%;height:4px;border-radius:2px;background:var(--z-line)"><div style="height:4px;border-radius:2px;width:'+((c.count||0)/maxC*100).toFixed(0)+'%;background:var(--z-dim)"></div></div></td></tr>';
      });
      $('met-codes').innerHTML='<div class="card"><div class="p-3 px-4" style="border-bottom:1px solid var(--z-line)"><span class="sec-label" style="margin:0">Response codes</span></div><table><thead><tr><th>Code</th><th>Reason</th><th>Count</th><th></th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }
  });
};

// ===== REPORTS =====
pages['/reports']=function(){
  $('main').innerHTML='<h1 class="t-lg">Reports</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">Traffic analysis and telecom KPIs</p>'+
    '<div class="grid grid-cols-2 lg:grid-cols-4 gap-3" id="rep-kpi"></div>'+
    '<div class="grid lg:grid-cols-2 gap-4 mt-5"><div class="card p-4"><div class="sec-label">ASR and ACD trend</div><div style="aspect-ratio:2.5/1;min-height:140px"><canvas id="rep-trend-chart"></canvas></div></div>'+
    '<div class="card p-4"><div class="sec-label">Call volume</div><div style="aspect-ratio:2.5/1;min-height:140px"><canvas id="rep-vol-chart"></canvas></div></div></div>'+
    '<div class="grid lg:grid-cols-2 gap-4 mt-5"><div id="rep-agents"></div><div id="rep-talkers"></div></div>'+
    '<div class="grid lg:grid-cols-2 gap-4 mt-5"><div id="rep-methods"></div><div id="rep-topcalls"></div></div>'+
    '<div class="mt-5" id="rep-daily"></div>';

  // Fetch all endpoints in parallel
  Promise.all([
    api('/api/realtime?window=1'),
    api('/api/report'),
    api('/api/report/agents'),
    api('/api/report/top-talkers?limit=15'),
    api('/api/report/top-calls?limit=20'),
    api('/api/nodes'),
    api('/api/trend/hourly?hours=24'),
  ]).then(([rt,summary,agents,talkers,topCalls,nodes,hourly])=>{

    // KPI cards from realtime (1 min window)
    if(rt){
      const asr=n(rt,'asr');
      const fails=n(rt,'resp_4xx')+n(rt,'resp_5xx');
      $('rep-kpi').innerHTML=
        kpi('Concurrent',fmt(n(rt,'active_calls')),'active calls','')+
        kpi('ASR',asr+'%','answer rate',asrColor(asr))+
        kpi('ACD',n(rt,'acd_seconds')+'s','avg duration','')+
        kpi('Failed',fmt(fails),'4xx + 5xx',errColor(fails));
    }

    // Per-agent breakdown
    if(agents&&agents.length){
      // Calculate per-agent share
      const totalMsgs=agents.reduce((s,a)=>s+n(a,'messages'),0)||1;
      let rows='';
      agents.forEach(a=>{
        const msgs=n(a,'messages');
        const pct=(msgs/totalMsgs*100).toFixed(1);
        rows+='<tr>'+
          '<td>'+agentHtml(a.agent)+'</td>'+
          '<td class="mono">'+msgs.toLocaleString()+'</td>'+
          '<td class="mono">'+n(a,'calls').toLocaleString()+'</td>'+
          '<td><div class="flex items-center gap-2"><div class="flex-1 rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full bg-[var(--z-ok)]" style="width:'+pct+'%"></div></div><span class="mono t-xs" style="color:var(--z-sub)">'+pct+'%</span></div></td>'+
          '<td class="text-[var(--z-muted)]">'+(a.last_seen?timeAgo(a.last_seen):'')+'</td></tr>';
      });
      $('rep-agents').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0" style="color:var(--z-ink)">Traffic by Server</div><div class="t-xs mt-1" style="color:var(--z-sub)">Message and call distribution across HEP agents.</div></div><table><thead><tr><th>Server</th><th>Messages</th><th>Call IDs</th><th>Share</th><th>Last Seen</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }

    // Top talkers
    if(talkers&&talkers.length){
      const maxMsgs=n(talkers[0],'messages')||1;
      let rows='';
      talkers.forEach((t,i)=>{
        const ip=(t.src||'').split(':')[0];
        const msgs=n(t,'messages');
        const pct=(msgs/maxMsgs*100).toFixed(0);
        rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ip?addr='+encodeURIComponent(ip)+'\'">'+
          '<td class="mono t-xs" style="color:var(--z-sub)">'+(i+1)+'</td>'+
          '<td class="mono c-id">'+h(t.src||'')+'</td>'+
          '<td class="mono">'+msgs.toLocaleString()+'</td>'+
          '<td class="mono">'+n(t,'calls').toLocaleString()+'</td>'+
          '<td><div class="w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full bg-[var(--z-ok)]" style="width:'+pct+'%"></div></div></td></tr>';
      });
      $('rep-talkers').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0" style="color:var(--z-ink)">Top Endpoints</div><div class="t-xs mt-1" style="color:var(--z-sub)">Busiest source IPs. Click to view IP history.</div></div><table><thead><tr><th>#</th><th>Endpoint</th><th>Msgs</th><th>Calls</th><th>Volume</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }

    // Method breakdown from summary
    if(summary&&summary.methods){
      const methods=summary.methods;
      // Aggregate response codes (prefixed with status code) vs requests
      const buckets={INVITE:0,BYE:0,ACK:0,OPTIONS:0,REGISTER:0,CANCEL:0,PRACK:0,other:0};
      const responses={'2xx':0,'3xx':0,'4xx':0,'5xx':0};
      Object.keys(methods).forEach(k=>{
        const c=methods[k];
        const parts=k.split(' ');
        if(parts.length===2){
          // Response: "200 INVITE" or "1 INVITE" (1xx)
          const code=parseInt(parts[0]);
          if(code>=200&&code<300) responses['2xx']+=c;
          else if(code>=300&&code<400) responses['3xx']+=c;
          else if(code>=400&&code<500) responses['4xx']+=c;
          else if(code>=500) responses['5xx']+=c;
          else if(code>=1&&code<10){
            // 1xx provisional stored as "1 INVITE"
            responses['2xx']+=0; // skip 1xx
          }
        } else {
          // Request
          const m=k.toUpperCase();
          if(buckets[m]!==undefined) buckets[m]+=c;
          else buckets.other+=c;
        }
      });
      const total=Object.values(buckets).reduce((s,v)=>s+v,0)||1;
      let mRows='';
      Object.entries(buckets).filter(([,v])=>v>0).sort((a,b)=>b[1]-a[1]).forEach(([m,c])=>{
        const pct=(c/total*100).toFixed(1);
        const color=m==='INVITE'?'#c084fc':m==='BYE'?themeColor('warn'):m==='REGISTER'?themeColor('ok'):m==='OPTIONS'?themeColor('dim'):themeColor('sub');
        mRows+='<tr><td class="font-medium" style="color:'+color+'">'+h(m)+'</td><td class="mono">'+c.toLocaleString()+'</td><td class="mono t-xs" style="color:var(--z-sub)">'+pct+'%</td>'+
          '<td><div class="w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full" style="background:'+color+';width:'+pct+'%"></div></div></td></tr>';
      });
      // Response code summary
      const rTotal=Object.values(responses).reduce((s,v)=>s+v,0)||1;
      let rRows='';
      [['2xx',themeColor('ok')],['3xx',themeColor('sub')],['4xx',themeColor('warn')],['5xx',themeColor('err')]].forEach(([code,color])=>{
        const c=responses[code];
        if(c>0){
          rRows+='<tr><td class="mono font-medium" style="color:'+color+'">'+code+'</td><td class="mono">'+c.toLocaleString()+'</td><td class="mono t-xs" style="color:var(--z-sub)">'+(c/rTotal*100).toFixed(1)+'%</td>'+
            '<td><div class="w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full" style="background:'+color+';width:'+(c/rTotal*100).toFixed(0)+'%"></div></div></td></tr>';
        }
      });
      $('rep-methods').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0" style="color:var(--z-ink)">Request Methods</div><div class="t-xs mt-1" style="color:var(--z-sub)">'+n(summary,'total').toLocaleString()+' total messages · '+n(summary,'unique_call_ids').toLocaleString()+' unique Call-IDs</div></div><table><thead><tr><th>Method</th><th>Count</th><th>%</th><th>Volume</th></tr></thead><tbody>'+mRows+'</tbody></table>'+
        (rRows?'<div class="p-4 pt-3" style="border-top:1px solid var(--z-line)"><div class="sec-label mb-2">Response Codes</div><table><thead><tr><th>Class</th><th>Count</th><th>%</th><th>Volume</th></tr></thead><tbody>'+rRows+'</tbody></table></div>':'')+
        '</div>';
    }

    // Top calls
    if(topCalls&&topCalls.length){
      let rows='';
      topCalls.forEach(c=>{
        const st=c.state==='active'?'<span class="c-ok">active</span>':'<span style="color:var(--z-sub)">'+h(c.state||'')+'</span>';
        const from=(c.from||'').replace(/<[^>]*>/g,'').replace(/;.*/,'').trim()||'-';
        const to=(c.to||'').replace(/<[^>]*>/g,'').replace(/;.*/,'').trim()||'-';
        rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(c.call_id||'')+'\'">'+
          '<td class="mono c-id truncate max-w-[200px]">'+h(c.call_id||'')+'</td>'+
          '<td class="mono">'+n(c,'messages')+'</td>'+
          '<td>'+st+'</td>'+
          '<td class="truncate max-w-[150px]">'+h(from)+'</td>'+
          '<td class="truncate max-w-[150px]">'+h(to)+'</td>'+
          '<td class="text-[var(--z-muted)]">'+(c.ts_first?timeAgo(c.ts_first):'')+'</td></tr>';
      });
      $('rep-topcalls').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0" style="color:var(--z-ink)">Top Calls by Messages</div><div class="t-xs mt-1" style="color:var(--z-sub)">Calls with the most SIP messages. Click for ladder.</div></div><table><thead><tr><th>Call-ID</th><th>Msgs</th><th>State</th><th>From</th><th>To</th><th>Started</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }

    // Overall summary stats
    if(summary){
      const span=n(summary,'ts_max')-n(summary,'ts_min');
      const hours=(span/3600000).toFixed(1);
      $('rep-daily').innerHTML='<div class="card p-4"><div class="flex flex-wrap gap-4 text-xs">'+
        '<div><span style="color:var(--z-sub)">Total messages:</span> <span class="mono font-medium">'+n(summary,'total').toLocaleString()+'</span></div>'+
        '<div><span style="color:var(--z-sub)">Unique Call-IDs:</span> <span class="mono font-medium">'+n(summary,'unique_call_ids').toLocaleString()+'</span></div>'+
        '<div><span style="color:var(--z-sub)">HEP captured:</span> <span class="mono font-medium">'+n(summary,'hep').toLocaleString()+'</span></div>'+
        '<div><span style="color:var(--z-sub)">Time span:</span> <span class="mono font-medium">'+hours+' hours</span></div>'+
        '<div><span style="color:var(--z-sub)">Avg msgs/sec:</span> <span class="mono font-medium">'+perSec(n(summary,'total'),span/1000)+'</span></div>'+
        '</div></div>';
    }

    // Historical trend charts
    if(hourly&&hourly.length>1){
      const _d=themeColor('dim'),_l=themeColor('line');
      const chartOpts={responsive:true,maintainAspectRatio:false,animation:{duration:0},plugins:{legend:{position:'top',align:'end',labels:{boxWidth:6,padding:10,font:{size:11},color:_d}}},scales:{x:{ticks:{maxTicksToLimit:12,font:{size:10},color:_d},grid:{display:false}},y:{beginAtZero:true,ticks:{font:{size:10},color:_d},grid:{color:_l}}}};
      const labels=hourly.map(h=>{const d=new Date(h.ts);return d.toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit'});});

      // ASR/ACD trend
      const tc=$('rep-trend-chart');
      if(tc){
        const asrData=hourly.map(h=>h.asr);
        const acdData=hourly.map(h=>h.acd);
        new Chart(tc,{type:'line',data:{labels,datasets:[
          {label:'ASR %',data:asrData,borderColor:themeColor('ok'),borderWidth:1.5,pointRadius:0,fill:false,tension:0.3,yAxisID:'y'},
          {label:'ACD (s)',data:acdData,borderColor:themeColor('sub'),borderWidth:1.5,pointRadius:0,fill:false,tension:0.3,yAxisID:'y1'}
        ]},options:{...chartOpts,scales:{...chartOpts.scales,y:{...chartOpts.scales.y,position:'left',title:{display:true,text:'ASR %',font:{size:9},color:themeColor('dim')}},y1:{position:'right',beginAtZero:true,ticks:{font:{size:9},color:themeColor('dim')},grid:{display:false},title:{display:true,text:'ACD (s)',font:{size:9},color:themeColor('dim')}}}}});
      }

      // Volume trend
      const vc=$('rep-vol-chart');
      if(vc){
        new Chart(vc,{type:'bar',data:{labels,datasets:[
          {label:'Answered',data:hourly.map(h=>h.answered),backgroundColor:'rgba(52,211,153,0.6)',borderRadius:2},
          {label:'Failed',data:hourly.map(h=>h.failed),backgroundColor:'rgba(248,113,113,0.6)',borderRadius:2}
        ]},options:{...chartOpts,scales:{...chartOpts.scales,x:{...chartOpts.scales.x,stacked:true},y:{...chartOpts.scales.y,stacked:true}}}});
      }
    }
  });
};

// ===== SLA =====
pages['/sla']=function(){
  $('main').innerHTML='<h1 class="t-lg">SLA</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">Service level targets — click a gauge to adjust</p>'+
    '<div id="sla-summary"></div>'+
    '<div class="grid lg:grid-cols-2 gap-4 mt-5"><div id="sla-agents"></div><div id="sla-errors"></div></div>'+
    '<div class="grid lg:grid-cols-2 gap-4 mt-5"><div id="sla-dests"></div><div id="sla-srcs"></div></div>';

  // SLA targets — stored in localStorage
  const defaults={asr:70,ner:90,err_rate:5,acd_min:30};
  function targets(){try{return{...defaults,...JSON.parse(localStorage.getItem('zaman_sla_targets')||'{}')};}catch(e){return defaults;}}
  function saveTargets(t){localStorage.setItem('zaman_sla_targets',JSON.stringify(t));}

  function gauge(label,value,unit,target,invert){
    const met=invert?(value<=target):(value>=target);
    const warn=invert?(value<=target*1.5):(value>=target*0.7);
    const cls=met?'c-ok':warn?'c-warn':'c-err';
    const status=met?'Met':warn?'At risk':'Breach';
    const pct=Math.min(100,invert?Math.max(0,(1-value/Math.max(target*2,1))*100):Math.min(100,value/Math.max(target,1)*100));
    return '<div class="card p-4 cursor-pointer" onclick="editTarget(\''+label+'\')">'+
      '<div class="flex items-center justify-between mb-2"><div class="t-xs" style="color:var(--z-dim)">'+h(label)+'</div><span class="t-xs '+cls+'" style="font-weight:500">'+status+'</span></div>'+
      '<div class="t-hero mono '+cls+'">'+value+unit+'</div>'+
      '<div class="mt-2 w-full" style="height:3px;border-radius:2px;background:var(--z-line)"><div style="height:3px;border-radius:2px;width:'+pct+'%;background:var(--z-'+( met?'ok':warn?'warn':'err')+')"></div></div>'+
      '<div class="flex justify-between mt-1 t-xs" style="color:var(--z-dim)"><span>target '+(invert?'≤':'≥')+target+unit+'</span></div></div>';
  }

  window.editTarget=function(label){
    const t=targets();
    const key=label==='ASR'?'asr':label==='NER'?'ner':label==='Error Rate'?'err_rate':label==='ACD'?'acd_min':null;
    if(!key) return;
    const v=prompt('Set SLA target for '+label+' (current: '+t[key]+'):',t[key]);
    if(v===null) return;
    const num=parseFloat(v);
    if(isNaN(num)) return;
    t[key]=num;
    saveTargets(t);
  };

  async function refreshSLA(){
    const t=targets();
    const [rt1,rt5,nodes]=await Promise.all([api('/api/realtime?window=1'),api('/api/realtime?window=5'),api('/api/nodes')]);

    // Use 5-min window for SLA gauges — more representative than 1-min
    const sla=rt5||rt1;
    if(sla){
      const invites=n(sla,'invites');
      const answered=n(sla,'answered_calls');
      const failed=n(sla,'failed_calls');
      const total4xx5xx=n(sla,'resp_4xx')+n(sla,'resp_5xx');
      const totalResp=n(sla,'resp_2xx')+total4xx5xx;
      // ASR = answered / (answered + failed) — only completed calls, excludes ringing
      const completed=answered+failed;
      const asr=completed>0?Math.round(answered*100/completed):0;
      // NER = (completed - failed) / completed — same base
      const ner=completed>0?Math.round((completed-failed)*100/completed):0;
      const errRate=totalResp>0?Math.round(total4xx5xx*100/totalResp):0;
      const acd=n(sla,'acd_seconds');
      const active=n(sla,'active_calls');

      $('sla-summary').innerHTML='<div class="grid grid-cols-2 xl:grid-cols-4 gap-4">'+
        gauge('ASR',asr,'%',t.asr,false)+
        gauge('NER',ner,'%',t.ner,false)+
        gauge('Error Rate',errRate,'%',t.err_rate,true)+
        gauge('ACD',acd,'s',t.acd_min,false)+
        '</div>'+
        '<div class="grid grid-cols-2 xl:grid-cols-5 gap-3 mt-4">'+
        kpi('Concurrent Calls',active,'open dialogs','c-muted')+
        kpi('Invites 5m',invites,'call attempts','c-muted')+
        kpi('Answered',answered,'completed calls','c-ok')+
        kpi('Failed',failed,'4xx/5xx','c-err')+
        kpi('Sources',n(rt1,'sources'),'unique IPs','c-muted')+
        '</div>';
    }

    // Per-agent SLA
    if(nodes&&nodes.length){
      const agentData=await Promise.all(nodes.map(nd=>api('/api/realtime?window=5&agent='+encodeURIComponent(nd.agent))));
      let rows='';
      nodes.forEach((nd,i)=>{
        const a=agentData[i]||{};
        const agent=nd.agent||'';
        const inv=n(a,'invites');
        const ans=n(a,'answered_calls');
        const fail=n(a,'failed_calls');
        const completed=ans+fail;
        const asr=completed>0?Math.round(ans*100/completed):0;
        const acd=n(a,'acd_seconds');
        const s=nd.status||'red';
        const dot=s==='green'?'dot-green':s==='yellow'?'dot-yellow':'dot-red';
        const asrColor=asr>=t.asr?'var(--z-ok)':asr>=t.asr*0.7?'var(--z-warn)':'var(--z-err)';
        rows+='<tr>'+
          '<td><span class="flex items-center gap-2"><span class="w-2 h-2 rounded-full '+dot+'"></span>'+agentHtml(agent)+'</span></td>'+
          '<td class="mono">'+n(a,'total')+'</td>'+
          '<td class="mono">'+inv+'</td>'+
          '<td class="mono">'+ans+'</td>'+
          '<td class="mono">'+fail+'</td>'+
          '<td class="mono" style="color:'+asrColor+'">'+asr+'%</td>'+
          '<td class="mono">'+acd+'s</td>'+
          '<td class="mono">'+n(nd,'active_calls')+'</td>'+
          '</tr>';
      });
      $('sla-agents').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0" style="color:var(--z-ink)">Per-Server SLA (5 min)</div></div><table><thead><tr><th>Server</th><th>Total</th><th>Invites</th><th>Answered</th><th>Failed</th><th>ASR</th><th>ACD</th><th>Active</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }

    // Error breakdown
    if(rt5){
      const codes=[
        {label:'401 Unauthorized',val:n(rt5,'err_401'),color:themeColor('warn')},
        {label:'403 Forbidden',val:n(rt5,'err_403'),color:themeColor('warn')},
        {label:'404 Not Found',val:n(rt5,'err_404'),color:themeColor('dim')},
        {label:'486 Busy',val:n(rt5,'err_486'),color:themeColor('sub')},
        {label:'503 Unavailable',val:n(rt5,'err_503'),color:themeColor('err')},
        {label:'Other 4xx',val:n(rt5,'resp_4xx')-n(rt5,'err_401')-n(rt5,'err_403')-n(rt5,'err_404')-n(rt5,'err_486'),color:themeColor('dim')},
        {label:'5xx',val:n(rt5,'resp_5xx')-n(rt5,'err_503'),color:themeColor('err')},
      ].filter(c=>c.val>0);
      const total=codes.reduce((s,c)=>s+c.val,0)||1;
      let bars='';
      codes.forEach(c=>{
        const pct=(c.val/total*100).toFixed(1);
        bars+='<div class="flex items-center gap-3 py-2" style="border-bottom:1px solid var(--z-line)"><div class="w-28 text-xs">'+c.label+'</div><div class="flex-1"><div class="w-full rounded-full h-2" style="background:var(--z-line)"><div class="h-2 rounded-full" style="background:'+c.color+';width:'+pct+'%"></div></div></div><div class="mono t-xsw-16 text-right">'+c.val+'</div><div class="t-xs w-12 text-right" style="color:var(--z-sub)">'+pct+'%</div></div>';
      });
      if(!bars) bars='<div class="py-4 text-sm" style="color:var(--z-sub)">No errors in the last 5 minutes.</div>';
      $('sla-errors').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0" style="color:var(--z-ink)">Error Breakdown (5 min)</div></div><div class="p-4">'+bars+'</div></div>';
    }

    // Per-destination IP ASR/ACD
    const [dests,srcs]=await Promise.all([api('/api/sla/destinations'),api('/api/sla/sources')]);

    function ipTable(data,label,ipField,elId){
      if(!data||!data.length){$(elId).innerHTML='';return;}
      let rows='';
      data.forEach(d=>{
        const ip=d[ipField]||'';
        const asr=d.asr||0;
        const acd=d.acd||0;
        const asrColor=asr>=70?'c-ok':asr>=40?'c-warn':'c-err';
        rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ip?addr='+encodeURIComponent(ip)+'\'">'+
          '<td class="mono c-accent">'+h(ip)+'</td>'+
          '<td class="mono">'+n(d,'invites')+'</td>'+
          '<td class="mono c-ok">'+n(d,'ok_2xx')+'</td>'+
          '<td class="mono '+(n(d,'errors')>0?'c-err':'')+'">'+n(d,'errors')+'</td>'+
          '<td class="mono '+asrColor+'">'+asr+'%</td>'+
          '<td class="mono">'+acd+'s</td></tr>';
      });
      $(elId).innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">'+label+'</div><div class="t-xs mt-1" style="color:var(--z-sub)">ASR and ACD per IP (5 min window). Click to view history.</div></div><table><thead><tr><th>IP</th><th>Attempts</th><th>Answered</th><th>Failed</th><th>ASR</th><th>ACD</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }
    ipTable(dests,'Destination IPs (Carriers)','dst','sla-dests');
    ipTable(srcs,'Source IPs (Origins)','src','sla-srcs');
  }
  poll(refreshSLA,5000);
};

// ===== ALERTS =====
pages['/alerts']=function(){
  $('main').innerHTML='<h1 class="t-lg">Alerts</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">Live anomaly detection from the last 5 minutes</p>'+
    '<div id="al-status"></div><div class="mt-5" id="al-codes"></div>';
  async function refreshAlerts(){
    const [anomalies,codes]=await Promise.all([api('/api/anomalies'),api('/api/report/response-codes')]);
    if(anomalies&&anomalies.length){
      let rows='';
      anomalies.forEach(a=>{
        const sev=a.severity==='critical'?'c-err':'c-warn';
        const icon=a.severity==='critical'?'&#x26A0;':'&#x26A0;';
        rows+='<div class="flex items-center gap-3 p-3" style="border-bottom:1px solid var(--z-line)">'+
          '<span class="'+sev+'">'+icon+'</span>'+
          '<div class="flex-1"><div class="sec-label" style="margin:0">'+h(a.message||a.type)+'</div><div class="t-xs" style="color:var(--z-sub)">'+h(a.type)+' · '+n(a,'count')+' occurrences</div></div>'+
          '<span class="t-xs font-medium '+sev+'">'+h(a.severity)+'</span></div>';
      });
      $('al-status').innerHTML='<div class="card">'+rows+'</div>';
    } else {
      $('al-status').innerHTML='<div class="card p-4 text-center"><div class="c-ok text-lg mb-1">&#x2714;</div><div class="sec-label" style="margin:0">No anomalies detected</div><div class="t-xs mt-1" style="color:var(--z-sub)">All metrics within normal thresholds</div></div>';
    }
    if(codes&&codes.length){
      let rows='';
      const maxCnt=Math.max(...codes.map(c=>c.count||0))||1;
      codes.forEach(c=>{
        const st=c.status||0;
        const color=st>=500?'c-err':st>=400?'c-warn':st>=300?'c-muted':st>=200?'c-ok':'';
        const pct=((c.count||0)/maxCnt*100).toFixed(0);
        rows+='<tr><td class="mono '+color+'">'+st+'</td><td>'+h(c.reason||'')+'</td><td class="mono">'+n(c,'count').toLocaleString()+'</td>'+
          '<td><div class="w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full" style="width:'+pct+'%;background:var(--z-muted)"></div></div></td></tr>';
      });
      $('al-codes').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">Response Code Distribution</div><div class="t-xs mt-1" style="color:var(--z-sub)">From recent 50K messages</div></div><table><thead><tr><th>Code</th><th>Reason</th><th>Count</th><th>Volume</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }
  }
  refreshAlerts();
  poll(refreshAlerts,10000);

  // Load alert config
  fetch('/api/alerts/config',{headers:headers()}).then(r=>r.ok?r.json():null).then(cfg=>{
    if(!cfg)return;
    const webhooks=(cfg.webhooks||[]).join('\n');
    $('al-codes').insertAdjacentHTML('afterend',
      '<div class="card p-4 mt-5"><div class="sec-label" style="margin:0 mb-3">Alert Configuration</div>'+
      '<div class="grid xl:grid-cols-2 gap-4">'+
      '<div><label class="t-xs font-medium" style="color:var(--z-dim)">Webhook URLs (one per line)</label>'+
      '<textarea id="al-webhooks" rows="3" class="w-full mt-1 rounded-md t-xsmono p-2" style="background:var(--z-field);border:1px solid var(--z-line);color:var(--z-ink);resize:vertical">'+h(webhooks)+'</textarea></div>'+
      '<div><label class="t-xs font-medium" style="color:var(--z-dim)">Thresholds</label>'+
      '<div class="grid grid-cols-2 gap-2 mt-1">'+
      '<div><span class="t-xs" style="color:var(--z-dim)">Min ASR %</span><input id="al-asr" type="number" value="'+(cfg.thresholds?.asr_min||70)+'" class="w-full mt-0.5 text-xs"></div>'+
      '<div><span class="t-xs" style="color:var(--z-dim)">Max Error Rate %</span><input id="al-err" type="number" value="'+(cfg.thresholds?.err_rate_max||10)+'" class="w-full mt-0.5 text-xs"></div></div>'+
      '<button onclick="saveAlertConfig()" class="mt-3 rounded-md px-3 py-1.5 sec-label" style="margin:0 cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Save</button></div></div></div>');
  });
  window.saveAlertConfig=async function(){
    const webhooks=$('al-webhooks').value.split('\n').map(s=>s.trim()).filter(Boolean);
    const config={webhooks,thresholds:{asr_min:parseInt($('al-asr').value)||70,err_rate_max:parseInt($('al-err').value)||10}};
    await fetch('/api/alerts/config',{method:'POST',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify(config)});
    alert('Alert config saved.');
  };
};

// ===== QOS =====
pages['/qos']=async function(){
  $('main').innerHTML='<h1 class="t-lg">Call Quality</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">Aggregate QoS from RTCP data.</p><div id="qos-c"></div>';
  $('qos-c').innerHTML='<div class="card p-4 t-sm" style="color:var(--z-sub)">No RTCP data available yet. Configure your media server to send HEP type 5 (RTCP) to zaman on port 9060.</div>';
};

// ===== IP =====
pages['/ip']=function(params){
  const preIP=params?params.get('addr')||'':'';
  $('main').innerHTML='<h1 class="t-lg">IP History</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">Traffic analysis for a specific endpoint</p>'+
    '<div class="flex gap-2 mb-5"><input id="ip-addr" placeholder="Enter an IP address (e.g. 44.196.20.220)" value="'+h(preIP)+'" class="flex-1">'+
    '<button onclick="ipLookup()" class="rounded-md px-3 py-1.5 sec-label" style="margin:0 cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Search</button></div>'+
    '<div id="ip-geo" class="mb-4"></div>'+
    '<div id="ip-summary"></div>'+
    '<div id="ip-carrier" class="mb-5"></div>'+
    '<div id="ip-r"></div>'+
    '<div id="ip-top" class="mt-5"></div>';

  // Show top talkers on initial load (before any search)
  if(!preIP){
    api('/api/report/top-talkers?limit=20').then(talkers=>{
      if(!talkers||!talkers.length)return;
      let rows='';
      talkers.forEach((t,i)=>{
        const ip=(t.src||'').split(':')[0];
        rows+='<tr class="cursor-pointer" onclick="$(\'ip-addr\').value=\''+h(ip)+'\';ipLookup()">'+
          '<td class="mono t-xs" style="color:var(--z-dim)">'+(i+1)+'</td>'+
          '<td class="mono c-accent">'+h(t.src||'')+'</td>'+
          '<td class="mono">'+n(t,'messages').toLocaleString()+'</td>'+
          '<td class="mono">'+n(t,'calls').toLocaleString()+'</td>'+
          '</tr>';
      });
      $('ip-top').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">Top Endpoints</div><div class="t-xs mt-1" style="color:var(--z-sub)">Click an IP to view its traffic history.</div></div><table><thead><tr><th>#</th><th>Endpoint</th><th>Messages</th><th>Calls</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    });
  }

  $('ip-addr').addEventListener('keydown',e=>{if(e.key==='Enter')ipLookup();});

  window.ipLookup=async function(){
    const ip=$('ip-addr').value.trim();
    if(!ip) return;
    $('ip-top').innerHTML='';
    $('ip-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-sub)">Searching...</div>';
    $('ip-summary').innerHTML='';

    const msgs=await api('/api/messages?limit=300&ip='+encodeURIComponent(ip));
    if(!msgs||!msgs.length){$('ip-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-sub)">No messages found for '+h(ip)+'.</div>';return;}

    // Build summary stats from results
    const methods={},peers=new Set(),callIds=new Set(),calls={};
    let asSrc=0,asDst=0;
    msgs.forEach(m=>{
      const meth=m.method||'?';
      methods[meth]=(methods[meth]||0)+1;
      const cid=m.call_id;
      if(cid)callIds.add(cid);
      const srcIp=(m.src||'').split(':')[0];
      const dstIp=(m.dst||'').split(':')[0];
      if(srcIp===ip){asSrc++;peers.add(m.dst||'');}
      if(dstIp===ip){asDst++;peers.add(m.src||'');}
      // Track per-call for ASR/ACD
      if(cid){
        if(!calls[cid])calls[cid]={invite:false,answered:false,bye:false,inviteTs:0,byeTs:0,status:0};
        if(meth==='INVITE'&&m.kind==='request'){calls[cid].invite=true;if(!calls[cid].inviteTs)calls[cid].inviteTs=m.ts_ms||0;}
        const st=m.status||0;
        if(meth==='INVITE'&&st>=200&&st<300){calls[cid].answered=true;}
        if(st>=400)calls[cid].status=st;
        if(meth==='BYE'){calls[cid].bye=true;calls[cid].byeTs=m.ts_ms||0;}
      }
    });
    // Compute ASR / ACD / failure breakdown
    let invites=0,answered=0,failed=0,durations=[];
    const failCodes={};
    Object.values(calls).forEach(c=>{
      if(!c.invite)return;
      invites++;
      if(c.answered){answered++;if(c.bye&&c.byeTs&&c.inviteTs){const d=Math.round((c.byeTs-c.inviteTs)/1000);if(d>0&&d<7200)durations.push(d);}}
      else if(c.status>=400){failed++;const k=c.status;failCodes[k]=(failCodes[k]||0)+1;}
    });
    const asr=invites>0?Math.round(answered*100/invites):0;
    const acd=durations.length>0?Math.round(durations.reduce((a,b)=>a+b,0)/durations.length):0;
    const failList=Object.entries(failCodes).sort((a,b)=>b[1]-a[1]).map(([c,n])=>c+': '+n).join(', ');

    // Summary cards
    const methodList=Object.entries(methods).sort((a,b)=>b[1]-a[1]).map(([m,c])=>m+': '+c).join(' · ');
    $('ip-summary').innerHTML='<div class="grid grid-cols-2 xl:grid-cols-4 gap-3 mb-4">'+
      kpi('ASR',asr+'%','answered / '+invites+' INVITEs',asr>=70?'c-ok':asr>=40?'c-warn':'c-err')+
      kpi('ACD',acd+'s',durations.length+' completed calls','c-muted')+
      kpi('Answered',answered,'of '+invites+' attempts','c-ok')+
      kpi('Failed',failed,failList||'no failures',failed>0?'c-err':'c-ok')+
      '</div>'+
      '<div class="grid grid-cols-2 xl:grid-cols-5 gap-3 mb-4">'+
      kpi('Messages',msgs.length,'in sample','c-muted')+
      kpi('Call IDs',callIds.size,'unique calls','c-muted')+
      kpi('As source',asSrc,'outbound','c-ok')+
      kpi('As dest',asDst,'inbound','c-warn')+
      kpi('Peers',peers.size,'unique endpoints','c-muted')+
      '</div>'+
      '<div class="card p-4 px-4 mb-4 t-xs mono" style="color:var(--z-sub)">'+methodList+'</div>';

    // GeoIP + carrier scorecard (async, non-blocking)
    Promise.all([api('/api/geoip?ip='+encodeURIComponent(ip)),api('/api/sla/carrier?ip='+encodeURIComponent(ip))]).then(([geo,carrier])=>{
      // GeoIP card with map
      if(geo&&geo.status==='success'){
        let geoHtml='<div class="card"><div class="grid xl:grid-cols-[1fr_300px]"><div class="p-4"><div class="sec-label" style="margin:0 mb-3">Location</div>'+
          '<div class="grid grid-cols-2 gap-3 text-xs">'+
          '<div><span style="color:var(--z-dim)">City:</span> '+h(geo.city||'—')+'</div>'+
          '<div><span style="color:var(--z-dim)">Region:</span> '+h(geo.regionName||'—')+'</div>'+
          '<div><span style="color:var(--z-dim)">Country:</span> '+h(geo.country||'—')+'</div>'+
          '<div><span style="color:var(--z-dim)">ISP:</span> '+h(geo.isp||'—')+'</div>'+
          '<div><span style="color:var(--z-dim)">Org:</span> '+h(geo.org||'—')+'</div>'+
          '<div><span style="color:var(--z-dim)">AS:</span> <span class="mono">'+h(geo.as||'—')+'</span></div>'+
          '</div></div>'+
          '<div id="ip-map" style="height:180px;border-radius:0 10px 10px 0"></div></div></div>';
        $('ip-geo').innerHTML=geoHtml;
        // Render map
        if(geo.lat&&geo.lon&&window.L){
          const map=L.map('ip-map',{zoomControl:false,attributionControl:false}).setView([geo.lat,geo.lon],6);
          L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',{maxZoom:18}).addTo(map);
          L.circleMarker([geo.lat,geo.lon],{radius:8,color:'#8b5cf6',fillColor:'#8b5cf6',fillOpacity:0.6,weight:2}).addTo(map).bindPopup(h(ip)+' · '+h(geo.city||'')+', '+h(geo.country||''));
        }
      }
      // Carrier scorecard with trend chart
      if(carrier&&carrier.invites>0){
        let cHtml='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">Carrier Scorecard (60 min)</div></div>'+
          '<div class="grid grid-cols-2 xl:grid-cols-5 gap-3 p-4">'+
          kpi('ASR',carrier.asr+'%','answer rate',carrier.asr>=70?'c-ok':carrier.asr>=40?'c-warn':'c-err')+
          kpi('ACD',carrier.acd+'s','avg duration','c-muted')+
          kpi('Attempts',carrier.invites,'INVITEs','c-muted')+
          kpi('Answered',carrier.ok_2xx,'completed','c-ok')+
          kpi('Failed',carrier.errors,'rejected',carrier.errors>0?'c-err':'c-ok')+
          '</div>';
        // Error code breakdown
        if(carrier.error_codes&&Object.keys(carrier.error_codes).length){
          let codes='';
          Object.entries(carrier.error_codes).sort((a,b)=>b[1]-a[1]).forEach(([c,n])=>{
            codes+='<span class="mono t-xsc-warn">'+c+': '+n+'</span> ';
          });
          cHtml+='<div class="px-4 pb-3 t-xs" style="color:var(--z-dim)">Failure codes: '+codes+'</div>';
        }
        // Trend chart
        if(carrier.trend&&carrier.trend.length>1){
          cHtml+='<div class="px-4 pb-4" style="height:120px"><canvas id="ip-trend-chart"></canvas></div>';
        }
        cHtml+='</div>';
        $('ip-carrier').innerHTML=cHtml;
        // Render trend
        if(carrier.trend&&carrier.trend.length>1){
          const labels=carrier.trend.map(t=>{const d=new Date(t.m*60000);return d.toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit'});});
          const invD=carrier.trend.map(t=>t.inv);
          const ansD=carrier.trend.map(t=>t.ans);
          const ctx=$('ip-trend-chart');
          if(ctx)new Chart(ctx,{type:'line',data:{labels,datasets:[{label:'Attempts',data:invD,borderColor:'#38bdf8',borderWidth:1.5,pointRadius:0,fill:false,tension:0.3},{label:'Answered',data:ansD,borderColor:'#34d399',backgroundColor:'rgba(52,211,153,0.06)',borderWidth:1.5,pointRadius:0,fill:true,tension:0.3}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:0},plugins:{legend:{position:'bottom',labels:{boxWidth:8,font:{size:10},color:themeColor('sub')}}},scales:{x:{ticks:{maxTicksToLimit:8,font:{size:9},color:themeColor('dim')},grid:{display:false}},y:{beginAtZero:true,ticks:{font:{size:9},color:themeColor('dim')},grid:{color:'rgba(128,128,128,0.08)'}}}}});
        }
      }
    });

    // Message table
    let rows='';
    msgs.forEach(m=>{
      const st=m.status||0;
      const sc=st>=500?'c-err':st>=400?'c-warn':st>=200?'c-ok':'';
      const mc=m.method==='INVITE'?'c-invite':m.method==='BYE'?'c-bye':'';
      rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(m.call_id||'')+'\'">'+
        '<td class="mono '+mc+'">'+h(m.method||'')+'</td>'+
        '<td class="mono '+sc+'">'+(st||'')+'</td>'+
        '<td class="mono c-accent truncate max-w-[180px]">'+h(m.call_id||'')+'</td>'+
        '<td class="mono">'+h(m.src||'')+'</td>'+
        '<td class="mono">'+h(m.dst||'')+'</td>'+
        '<td>'+agentHtml(m.agent)+'</td>'+
        '<td style="color:var(--z-sub)">'+(m.ts_ms?timeAgo(m.ts_ms):'')+'</td></tr>';
    });
    $('ip-r').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">Traffic for '+h(ip)+'</div><div class="t-xs mt-1" style="color:var(--z-sub)">'+msgs.length+' messages · '+callIds.size+' calls · '+peers.size+' peers</div></div><table><thead><tr><th>Method</th><th>Code</th><th>Call-ID</th><th>Source</th><th>Destination</th><th>Server</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  };
  if(preIP) ipLookup();
};

// ===== PROBE =====
pages['/probe']=function(){
  window._probeHistory=window._probeHistory||[];
  $('main').innerHTML='<h1 class="t-lg">SIP Probe</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">Send SIP OPTIONS to test endpoint reachability and measure RTT</p>'+
    '<div class="card p-4 mb-5"><div class="flex gap-2 mb-2 flex-wrap"><input id="pr-host" placeholder="Hostname or IP" class="flex-1 min-w-[200px]"><input id="pr-port" placeholder="5060" class="w-24">'+
    '<button onclick="doProbe()" class="rounded-md px-3 py-1.5 sec-label" style="margin:0 cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Probe</button></div>'+
    '<div class="t-xs" style="color:var(--z-dim)">Sends SIP OPTIONS and waits for a response. Requires ZAMAN_PROBE=1 on the core.</div></div>'+
    '<div id="pr-r"></div><div id="pr-history"></div>';
  $('pr-host').addEventListener('keydown',e=>{if(e.key==='Enter')doProbe();});
  function renderHistory(){
    if(!window._probeHistory.length)return;
    let rows='';
    window._probeHistory.forEach((p,i)=>{
      const ok=p.ok;
      rows+='<tr><td class="'+(ok?'c-ok':'c-err')+'">'+(ok?'✓':'✗')+'</td><td class="mono">'+h(p.host||'')+'</td><td class="mono">'+h(p.port||'')+'</td>'+
        '<td class="mono">'+(ok?p.rtt_ms+'ms':'—')+'</td><td class="mono">'+(p.status||'—')+'</td><td style="color:var(--z-sub)">'+h(p.time||'')+'</td></tr>';
    });
    $('pr-history').innerHTML='<div class="card mt-5"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">Probe History</div></div><table><thead><tr><th></th><th>Host</th><th>Port</th><th>RTT</th><th>Status</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  }
  renderHistory();
  window.doProbe=async function(){
    const host=$('pr-host').value.trim(),port=parseInt($('pr-port').value)||5060;
    if(!host)return;
    $('pr-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-sub)">Probing '+h(host)+':'+port+'...</div>';
    try{
      const r=await fetch('/api/probe',{method:'POST',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify({host,port,wait_ms:3000})});
      const d=await r.json();
      const ok=d.ok===true;
      $('pr-r').innerHTML='<div class="card p-4"><div class="grid grid-cols-2 xl:grid-cols-4 gap-3">'+
        kpi('Result',ok?'Reachable':'Unreachable',h(d.error||''),ok?'c-ok':'c-err')+
        kpi('RTT',ok?d.rtt_ms+'ms':'—','round trip time',ok?'c-muted':'c-err')+
        kpi('Status',d.status||'—','SIP response code','c-muted')+
        kpi('Target',host+':'+port,'',ok?'c-ok':'c-err')+
        '</div></div>';
      window._probeHistory.unshift({ok,host,port,rtt_ms:d.rtt_ms,status:d.status,error:d.error,time:new Date().toLocaleTimeString()});
      if(window._probeHistory.length>20)window._probeHistory.pop();
      renderHistory();
    }catch(e){$('pr-r').innerHTML=errorCard('Probe failed: '+e.message);}
  };
};

// ===== ADMIN =====
pages['/admin']=function(){
  $('main').innerHTML='<h1 class="t-lg">Settings</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">System configuration and user management.</p>'+
    '<div class="grid xl:grid-cols-2 gap-4">'+
    '<div>'+
    '<div class="card p-4 mb-5"><div class="sec-label mb-2">API Key</div><div class="flex gap-2"><input id="ak" type="password" value="'+h(KEY)+'" class="flex-1"><button onclick="localStorage.setItem(\'zaman_api_key\',document.getElementById(\'ak\').value);location.reload()" class="rounded-md px-3 py-1.5 sec-label" style="margin:0 cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Save</button></div><p class="t-xs text-[var(--z-muted)] mt-2">Stored in localStorage. Sent as X-API-Key header with every request.</p></div>'+
    '<div class="card p-4"><div class="sec-label mb-2">System Health</div><div id="ah">Loading...</div></div>'+
    '</div>'+
    '<div>'+
    '<div class="card p-4 mb-5"><div class="sec-label mb-3">User Management</div><div id="user-list">Loading...</div>'+
    '<div class="mt-4 pt-4" style="border-top:1px solid var(--z-line)"><div class="sec-label mb-2">Add User</div>'+
    '<div class="flex gap-2 flex-wrap"><input id="nu-name" placeholder="Username" class="w-32"><input id="nu-pw" type="password" placeholder="Password" class="w-32">'+
    '<select id="nu-role" class="w-28"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select>'+
    '<button onclick="addUser()" class="rounded-md px-3 py-1.5 sec-label" style="margin:0 cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Add</button></div>'+
    '<div id="nu-err" class="t-xs c-err mt-1"></div></div></div>'+
    '</div></div>';

  async function loadUserList(){
    const users=await fetch('/web/users',{headers:headers()}).then(r=>r.ok?r.json():null);
    if(!users){$('user-list').innerHTML='<div class="t-xs" style="color:var(--z-sub)">Admin access required to manage users.</div>';return;}
    const roleBadge=r=>r==='admin'?'<span class="px-2 py-0.5 rounded-full t-xs font-semibold" style="background:rgba(248,113,113,.1);color:#f87171;border:1px solid rgba(248,113,113,.2)">admin</span>':r==='operator'?'<span class="px-2 py-0.5 rounded-full t-xs font-semibold" style="background:rgba(167,139,250,.1);color:#a78bfa;border:1px solid rgba(167,139,250,.2)">operator</span>':'<span class="px-2 py-0.5 rounded-full t-xs font-semibold" style="background:rgba(161,161,170,.1);color:#a1a1aa;border:1px solid rgba(161,161,170,.2)">viewer</span>';
    let rows='';
    users.forEach(u=>{
      rows+='<div class="flex items-center justify-between py-2.5" style="border-bottom:1px solid var(--z-line)">'+
        '<div class="flex items-center gap-2"><span class="t-sm font-medium">'+h(u.username)+'</span>'+roleBadge(u.role)+'</div>'+
        '<div class="flex gap-1">'+
        '<button onclick="resetPw('+u.id+',\''+h(u.username)+'\')" class="t-xs px-2 py-1 rounded" style="color:var(--z-sub);border:1px solid var(--z-line)">Reset pw</button>'+
        '<button onclick="deleteUser('+u.id+',\''+h(u.username)+'\')" class="t-xs px-2 py-1 rounded" style="color:#f87171;border:1px solid rgba(248,113,113,.2)">Delete</button>'+
        '</div></div>';
    });
    $('user-list').innerHTML=rows||'<div class="t-xs" style="color:var(--z-sub)">No users.</div>';
  }
  loadUserList();
  api('/api/health').then(d=>{if(d)$('ah').innerHTML='<pre class="t-xs mono p-3 rounded overflow-auto whitespace-pre-wrap" style="background:var(--z-field);border:1px solid var(--z-line)">'+h(JSON.stringify(d,null,2))+'</pre>';});

  window.addUser=async function(){
    const name=$('nu-name').value,pw=$('nu-pw').value,role=$('nu-role').value;
    $('nu-err').textContent='';
    if(!name||!pw){$('nu-err').textContent='Username and password required.';return;}
    const r=await fetch('/web/users',{method:'POST',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify({username:name,password:pw,role:role})});
    if(!r.ok){const e=await r.json().catch(()=>({}));$('nu-err').textContent=e.error||'Failed';return;}
    $('nu-name').value='';$('nu-pw').value='';
    loadUserList();
  };
  window.resetPw=async function(id,name){
    const pw=prompt('New password for '+name+':');
    if(!pw) return;
    await fetch('/web/users/password',{method:'POST',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify({id:id,password:pw})});
    alert('Password updated.');
  };
  window.deleteUser=async function(id,name){
    if(!confirm('Delete user '+name+'?')) return;
    const r=await fetch('/web/users',{method:'DELETE',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify({id:id})});
    if(!r.ok){const e=await r.json().catch(()=>({}));alert(e.error||'Failed');return;}
    loadUserList();
  };
};

// ===== NUMBER/DID SEARCH (accessible from IP History or directly) =====
pages['/number']=function(params){
  const preNum=params?params.get('q')||'':'';
  $('main').innerHTML='<h1 class="t-lg">Number Lookup</h1><p class="t-xs mt-1 mb-5" style="color:var(--z-sub)">Search call history by phone number or DID</p>'+
    '<div class="flex gap-2 mb-5"><input id="num-q" placeholder="Enter phone number (e.g. 7273491561)" value="'+h(preNum)+'" class="flex-1">'+
    '<button onclick="numSearch()" class="rounded-md px-3 py-1.5 sec-label" style="margin:0 cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Search</button></div>'+
    '<div id="num-r"></div>';
  $('num-q').addEventListener('keydown',e=>{if(e.key==='Enter')numSearch();});
  window.numSearch=async function(){
    const q=$('num-q').value.trim();if(!q)return;
    $('num-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-sub)">Searching...</div>';
    const d=await api('/api/number?q='+encodeURIComponent(q));
    if(!d||!d.total){$('num-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-sub)">No calls found for '+h(q)+'.</div>';return;}
    const asrColor=d.asr>=70?'c-ok':d.asr>=40?'c-warn':'c-err';
    let cards='<div class="grid grid-cols-2 xl:grid-cols-5 gap-3 mb-5">'+
      kpi('Total Calls',d.total,'in last 60 min','c-muted')+
      kpi('Answered',d.answered,'completed','c-ok')+
      kpi('Failed',d.failed,'rejected',d.failed>0?'c-err':'c-ok')+
      kpi('ASR',d.asr+'%','answer rate',asrColor)+
      kpi('ACD',d.acd+'s','avg duration','c-muted')+'</div>';
    let rows='';
    (d.calls||[]).forEach(c=>{
      const sc=c.state==='completed'?'c-ok':c.state==='failed'?'c-err':c.state==='in_progress'?'c-warn':'';
      rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(c.call_id||'')+'\'">'+
        '<td class="mono c-accent truncate max-w-[180px]">'+h(c.call_id||'')+'</td>'+
        '<td>'+agentHtml(c.agent)+'</td><td class="mono">'+h(c.src||'')+'</td><td class="mono">'+h(c.dst||'')+'</td>'+
        '<td class="'+sc+'">'+h(c.state)+'</td><td class="mono">'+(c.status||'')+'</td>'+
        '<td style="color:var(--z-sub)">'+(c.first_ts_ms?timeAgo(c.first_ts_ms):'')+'</td></tr>';
    });
    $('num-r').innerHTML=cards+'<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="sec-label" style="margin:0">Calls for '+h(q)+'</div></div><table><thead><tr><th>Call-ID</th><th>Server</th><th>Source</th><th>Destination</th><th>State</th><th>Code</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  };
  if(preNum)numSearch();
};

// ===== WALLBOARD MODE =====
pages['/wallboard']=function(){
  document.querySelector('aside').style.display='none';
  $('main').style.maxWidth='100%';$('main').style.padding='20px';
  $('main').innerHTML='<div id="wb" style="min-height:100vh"></div>';
  async function refreshWB(){
    const rt=await api('/api/realtime?window=1');
    if(!rt)return;
    const asr=n(rt,'asr');const fails=n(rt,'resp_4xx')+n(rt,'resp_5xx');
    $('wb').innerHTML='<div class="grid grid-cols-4 gap-4 mb-8">'+
      '<div class="card p-8 text-center"><div class="t-xs uppercase tracking-widest" style="color:var(--z-dim)">Concurrent Calls</div><div class="text-5xl font-bold mono mt-3 c-muted">'+n(rt,'active_calls').toLocaleString()+'</div></div>'+
      '<div class="card p-8 text-center"><div class="t-xs uppercase tracking-widest" style="color:var(--z-dim)">CPS</div><div class="text-5xl font-bold mono mt-3 c-ok">'+perSec(n(rt,'invites'),60)+'</div></div>'+
      '<div class="card p-8 text-center"><div class="t-xs uppercase tracking-widest" style="color:var(--z-dim)">ASR</div><div class="text-5xl font-bold mono mt-3 '+(asr>=70?'c-ok':asr>=40?'c-warn':'c-err')+'">'+asr+'%</div></div>'+
      '<div class="card p-8 text-center"><div class="t-xs uppercase tracking-widest" style="color:var(--z-dim)">Failures</div><div class="text-5xl font-bold mono mt-3 '+(fails>0?'c-err':'c-ok')+'">'+fails+'</div></div>'+
      '</div>'+
      '<div class="grid grid-cols-6 gap-4">'+
      '<div class="card p-4 text-center"><div class="t-xs" style="color:var(--z-dim)">Msg/sec</div><div class="text-2xl font-bold mono mt-1">'+perSec(n(rt,'total'),60)+'</div></div>'+
      '<div class="card p-4 text-center"><div class="t-xs" style="color:var(--z-dim)">ACD</div><div class="text-2xl font-bold mono mt-1">'+n(rt,'acd_seconds')+'s</div></div>'+
      '<div class="card p-4 text-center"><div class="t-xs" style="color:var(--z-dim)">2xx</div><div class="text-2xl font-bold mono mt-1 c-ok">'+n(rt,'resp_2xx').toLocaleString()+'</div></div>'+
      '<div class="card p-4 text-center"><div class="t-xs" style="color:var(--z-dim)">4xx</div><div class="text-2xl font-bold mono mt-1 c-warn">'+n(rt,'resp_4xx').toLocaleString()+'</div></div>'+
      '<div class="card p-4 text-center"><div class="t-xs" style="color:var(--z-dim)">5xx</div><div class="text-2xl font-bold mono mt-1 c-err">'+n(rt,'resp_5xx').toLocaleString()+'</div></div>'+
      '<div class="card p-4 text-center"><div class="t-xs" style="color:var(--z-dim)">Agents</div><div class="text-2xl font-bold mono mt-1">'+n(rt,'agents_active')+'</div></div>'+
      '</div>'+
      '<div class="text-center mt-5 t-xs" style="color:var(--z-dim)">Zaman · '+new Date().toLocaleTimeString()+'</div>';
  }
  poll(refreshWB,3000);
  // Restore sidebar on navigate away
  window.addEventListener('hashchange',function restore(){
    const aside=document.querySelector('aside');
    if(aside)aside.style.display='';
    $('main').style.maxWidth='1280px';$('main').style.padding='';
    window.removeEventListener('hashchange',restore);
  },{once:true});
};

// ===== KEYBOARD SHORTCUTS =====
document.addEventListener('keydown',function(e){
  if(e.target.tagName==='INPUT'||e.target.tagName==='SELECT'||e.target.tagName==='TEXTAREA')return;
  if(e.key==='/'&&!e.ctrlKey){e.preventDefault();location.hash='#/messages';setTimeout(()=>{const el=$('m-cid');if(el)el.focus();},100);}
  if(e.key==='Escape'){const d=$('msg-detail');if(d)d.style.display='none';}
  if(e.key==='w'&&!e.ctrlKey&&!e.metaKey){location.hash='#/wallboard';}
});

// Init
updateStatus();
navigate();
