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
function loadingCard(msg){return '<div class="card p-4 text-xs" style="color:var(--z-muted)">'+(msg||'Loading...')+'</div>';}
function errorCard(msg){return '<div class="card p-4 text-xs v-red">'+(msg||'Failed to load data. Check connection.')+'</div>';}
function h(s) { if (s==null) return ''; const d=document.createElement('div'); d.textContent=String(s); return d.innerHTML; }
function n(o,k) { return o&&o[k]!=null?o[k]:0; }

// Global node names — loaded once, used everywhere
window._nodeNames={};
(async()=>{try{const r=await fetch('/web/node-names',{headers:headers()});if(r.ok)window._nodeNames=await r.json();}catch(e){}})();
function agentName(agent){if(!agent)return'';const name=window._nodeNames[agent];return name?name:''+agent;}
function agentHtml(agent){if(!agent)return'';const name=window._nodeNames[agent];return name?h(name)+' <span class="text-[10px]" style="color:var(--z-muted)">('+h(agent)+')</span>':h(agent);}
function timeAgo(ms) {
  const s=Math.floor(Date.now()/1000-ms/1000);
  if(s<0) return 'just now';
  if(s<60) return s+'s ago';
  if(s<3600) return Math.floor(s/60)+'m ago';
  if(s<86400) return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago';
}
function mosColor(m){return m>=40?'#34d399':m>=30?'#fbbf24':'#ef4444'}

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
    el.innerHTML='<span class="w-2 h-2 rounded-full bg-[#34d399]"></span><span class="text-[#34d399]">core up</span><span class="text-[#3f3f46] ml-auto">uptime '+up+'s</span>';
  } else {
    el.innerHTML='<span class="w-2 h-2 rounded-full bg-[#ef4444]"></span><span class="text-[#ef4444]">core down</span>';
  }
}
setInterval(updateStatus,5000);

function kpi(label,value,sub,colorClass){
  const style=colorClass.startsWith('#')?'style="color:'+colorClass+'"':'class="'+colorClass+'"';
  return '<div class="card p-4"><div class="text-[10px] uppercase tracking-widest font-medium" style="color:var(--z-dim)">'+h(label)+'</div><div class="text-[1.375rem] font-semibold mono mt-1.5 leading-none" '+style+'>'+value+'</div><div class="text-[10px] mt-2 leading-snug" style="color:var(--z-muted)">'+h(sub)+'</div></div>';
}

// ===== OVERVIEW =====
pages['/']=function(){
  const m=$('main');
  m.innerHTML='<div class="flex items-center justify-between mb-6"><div><h1 class="text-lg font-semibold tracking-tight">Overview</h1><p class="text-xs mt-0.5" style="color:var(--z-muted)">Live operations across all servers</p></div><div><select id="ov-agent" onchange="window._ovAgent=this.value" class="text-xs"><option value="">All servers</option></select></div></div>'+
    '<div id="ov-hero"></div>'+
    '<div id="ov-kpis" class="mt-4"></div>'+
    '<div id="ov-charts" class="grid xl:grid-cols-[2fr_1fr] gap-5 mt-6" style="display:none"><div class="card p-4"><div class="text-xs font-medium mb-3">Traffic</div><div style="height:140px"><canvas id="ov-chart-traffic"></canvas></div></div>'+
    '<div class="card p-4"><div class="text-xs font-medium mb-3">Response Codes</div><div style="height:140px"><canvas id="ov-chart-codes"></canvas></div></div></div>'+
    '<div class="mt-6" id="ov-nodes"></div>'+
    '<div class="mt-6" id="ov-feed"></div>';
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
      const mps=perSec(n(rt,'total'),60);

      // Hero row — the 3 numbers that matter most, bigger
      $('ov-hero').innerHTML='<div class="grid grid-cols-3 gap-4">'+
        '<div class="card p-5"><div class="text-[10px] font-medium tracking-wide" style="color:var(--z-dim)">Concurrent calls</div><div class="text-3xl font-bold mono mt-2 v-pink">'+n(rt,'active_calls').toLocaleString()+'</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">active dialogs</div></div>'+
        '<div class="card p-5"><div class="text-[10px] font-medium tracking-wide" style="color:var(--z-dim)">CPS</div><div class="text-3xl font-bold mono mt-2 v-green">'+cps+'</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">calls per second</div></div>'+
        '<div class="card p-5"><div class="text-[10px] font-medium tracking-wide" style="color:var(--z-dim)">ASR</div><div class="text-3xl font-bold mono mt-2 '+(asr>=70?'v-green':asr>=40?'v-yellow':'v-red')+'">'+asr+'%</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">answer seizure ratio</div></div>'+
        '</div>';

      // Secondary metrics — compact row
      $('ov-kpis').innerHTML='<div class="grid grid-cols-5 gap-3">'+
        kpi('Msg rate',mps+'/s','captures/sec','v-blue')+
        kpi('Attempts',n(rt,'invites'),'INVITEs 1m','v-yellow')+
        kpi('Answered',n(rt,'answered_calls'),'completed','v-green')+
        kpi('Failures',fails,'4xx/5xx',fails>0?'v-red':'v-green')+
        kpi('ACD',n(rt,'acd_seconds')+'s','avg duration','v-purple')+
        '</div>';

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

      // Show charts after 2+ data points
      if(hist.labels.length>=2){
        const chartsEl=$('ov-charts');
        if(chartsEl) chartsEl.style.display='';

        const chartOpts={responsive:true,maintainAspectRatio:false,animation:{duration:300},plugins:{legend:{display:true,position:'bottom',labels:{boxWidth:8,padding:12,font:{size:10,family:'Inter'},color:'#71717a'}}},scales:{x:{display:true,ticks:{maxTicksToLimit:8,font:{size:9,family:'JetBrains Mono'},color:'#52525b'},grid:{display:false}},y:{display:true,beginAtZero:true,ticks:{font:{size:9,family:'JetBrains Mono'},color:'#52525b'},grid:{color:'rgba(128,128,128,0.08)'}}}};

        const tc=$('ov-chart-traffic');
        if(tc){
          if(window._ovCharts.traffic){window._ovCharts.traffic.data.labels=hist.labels;window._ovCharts.traffic.data.datasets[0].data=hist.total;window._ovCharts.traffic.data.datasets[1].data=hist.invites;window._ovCharts.traffic.update();}
          else{window._ovCharts.traffic=new Chart(tc,{type:'line',data:{labels:hist.labels,datasets:[{label:'Total',data:hist.total,borderColor:'#38bdf8',backgroundColor:'rgba(56,189,248,0.05)',borderWidth:1.5,pointRadius:0,fill:true,tension:0.3},{label:'INVITEs',data:hist.invites,borderColor:'#e879f9',borderWidth:1.5,pointRadius:0,fill:false,tension:0.3}]},options:chartOpts});}
        }

        const cc=$('ov-chart-codes');
        if(cc){
          const codeData=[n(rt,'resp_2xx'),n(rt,'resp_4xx'),n(rt,'resp_5xx')];
          if(window._ovCharts.codes){window._ovCharts.codes.data.datasets[0].data=codeData;window._ovCharts.codes.update();}
          else{window._ovCharts.codes=new Chart(cc,{type:'doughnut',data:{labels:['2xx','4xx','5xx'],datasets:[{data:codeData,backgroundColor:['#34d399','#fbbf24','#f87171'],borderWidth:0,hoverOffset:4}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:300},cutout:'65%',plugins:{legend:{position:'bottom',labels:{boxWidth:8,padding:12,font:{size:10,family:'Inter'},color:'#71717a'}}}}});}
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
          '<td class="mono v-pink">'+n(nd,'active_calls').toLocaleString()+'</td>'+
          '<td class="mono">'+n(nd,'calls').toLocaleString()+'</td>'+
          '<td class="mono'+(n(nd,'errors')>0?' v-red':'')+'">'+(n(nd,'errors')>0?n(nd,'errors'):'\u2014')+'</td>'+
          '<td style="color:var(--z-muted)">'+n(nd,'age_sec')+'s</td></tr>';
      });
      $('ov-nodes').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Servers</div></div><table><thead><tr><th>Node</th><th>Msgs 5m</th><th>Active</th><th>Call IDs</th><th>Errors</th><th>Seen</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
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
          '<td style="color:var(--z-muted)">'+(m.ts_ms?timeAgo(m.ts_ms):'')+'</td></tr>';
      });
      $('ov-feed').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Recent INVITEs</div></div><table><thead><tr><th>Call-ID</th><th>Source</th><th>Destination</th><th>Server</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }
  }
  poll(refreshOverview,5000);
};

// ===== CALLS =====
pages['/calls']=function(){
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">Calls</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Active call state tracking. Filter by IP, caller, or callee.</p>'+
    '<div class="flex gap-2 mb-4 flex-wrap">'+
    '<input id="cl-src" placeholder="Source IP" class="w-36">'+
    '<input id="cl-dst" placeholder="Dest IP" class="w-36">'+
    '<input id="cl-from" placeholder="From / Caller" class="w-36">'+
    '<input id="cl-to" placeholder="To / Callee" class="w-36">'+
    '<input id="cl-code" placeholder="Status code" class="w-28">'+
    '<select id="cl-state" class="w-28"><option value="">All states</option><option value="open">Ringing</option><option value="answered">Answered</option><option value="ended">Ended</option></select>'+
    '<button onclick="searchCalls()" class="rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Search</button>'+
    '<button onclick="document.querySelectorAll(\'#cl-src,#cl-dst,#cl-from,#cl-to,#cl-code\').forEach(e=>e.value=\'\');$(\'cl-state\').value=\'\';searchCalls()" class="rounded-lg px-3 py-1.5 text-xs font-medium cursor-pointer" style="border:1px solid var(--z-line);color:var(--z-muted)">Clear</button>'+
    '<a href="/api/export/csv?limit=500" target="_blank" class="rounded-lg px-3 py-1.5 text-xs font-medium cursor-pointer" style="border:1px solid var(--z-line);color:var(--z-muted);text-decoration:none">CSV</a></div>'+
    '<div class="flex gap-2 mb-5" style="border-bottom:1px solid var(--z-line);padding-bottom:1px">'+
    '<button onclick="$(\'cl-view-calls\').style.display=\'\';$(\'cl-view-carrier\').style.display=\'none\';this.style.borderBottom=\'2px solid var(--z-ink)\';this.nextElementSibling.style.borderBottom=\'none\'" class="px-3 py-2 text-xs font-medium cursor-pointer" style="border-bottom:2px solid var(--z-ink)">Calls</button>'+
    '<button onclick="$(\'cl-view-calls\').style.display=\'none\';$(\'cl-view-carrier\').style.display=\'\';this.style.borderBottom=\'2px solid var(--z-ink)\';this.previousElementSibling.style.borderBottom=\'none\';if(!window._carrierLoaded){window._carrierLoaded=true;loadCarriers();}" class="px-3 py-2 text-xs font-medium cursor-pointer" style="color:var(--z-muted)">Carrier Analysis</button></div>'+
    '<div id="cl-view-calls"><div id="cl-table"></div></div>'+
    '<div id="cl-view-carrier" style="display:none"><div class="flex items-center gap-3 mb-4">'+
    '<select id="ca-agent" class="text-xs"><option value="">All servers</option></select>'+
    '<button onclick="loadCarriers()" class="rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Analyze</button></div>'+
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
    $('cl-table').innerHTML='<div class="card p-4 text-sm text-[var(--z-muted)]">Loading...</div>';
    let calls=await api('/api/calls/active'+q);
    if(code&&calls){const c=parseInt(code);calls=calls.filter(x=>{const s=x.status||x.last_status||0;return c<10?String(s).startsWith(String(c)):s===c;});}
    if(!calls||!calls.length){$('cl-table').innerHTML='<div class="card p-4 text-sm text-[var(--z-muted)]">No calls found.</div>';return;}
    let rows='';
    calls.forEach(c=>{
      const st=n(c,'answered')?'<span class="text-[#34d399]">answered</span>':n(c,'open')?'<span class="text-[#fbbf24]">ringing</span>':'<span class="text-[#ef4444]">ended</span>';
      const sc=c.status||c.last_status||0;
      const scc=sc>=500?'text-[#ef4444]':sc>=400?'text-[#fbbf24]':sc>=200?'text-[#34d399]':'';
      rows+='<tr class="cursor-pointer hover:bg-[#131316]" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(c.call_id||'')+'\'"><td class="mono text-[#a78bfa] truncate max-w-[180px]">'+h(c.call_id||'')+'</td><td>'+agentHtml(c.agent)+'</td><td class="mono">'+h(c.src||'')+'</td><td class="mono">'+h(c.dst||'')+'</td><td>'+h(c.from_h||'')+'</td><td>'+h(c.to_h||'')+'</td><td class="mono '+scc+'">'+(sc||'')+'</td><td>'+st+'</td><td class="text-[var(--z-muted)]">'+(c.first_ts_ms?timeAgo(c.first_ts_ms):'')+'</td></tr>';
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
    $('ca-results').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-muted)">Analyzing traffic'+(agent?' for '+agentName(agent):'')+' ...</div>';
    let url='/api/messages?limit=500';
    if(agent) url+='&agent='+encodeURIComponent(agent);
    const msgs=await api(url);
    if(!msgs||!msgs.length){$('ca-results').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-muted)">No data.</div>';return;}

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
      const asrColor=asr>=70?'v-green':asr>=40?'v-yellow':'v-red';
      const codes=Object.entries(d.codes).sort((a,b)=>b[1]-a[1]).map(([c,n])=>c+':'+n).join(' ');
      rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ip?addr='+encodeURIComponent(dst)+'\'">'+
        '<td class="mono c-accent">'+h(dst)+'</td>'+
        '<td class="mono">'+d.attempts+'</td>'+
        '<td class="mono v-green">'+d.answered+'</td>'+
        '<td class="mono '+(d.failed>0?'v-red':'')+'">'+d.failed+'</td>'+
        '<td class="mono '+asrColor+'">'+asr+'%</td>'+
        '<td class="mono">'+acd+'s</td>'+
        '<td class="mono text-[10px]" style="color:var(--z-muted)">'+codes+'</td></tr>';
    });

    $('ca-results').innerHTML=
      '<div class="grid grid-cols-4 gap-3 mb-4">'+
      kpi('Overall ASR',overallAsr+'%',totalAnswered+' / '+totalAttempts+' via '+serverLabel,overallAsr>=70?'v-green':overallAsr>=40?'v-yellow':'v-red')+
      kpi('Overall ACD',overallAcd+'s',allDurations.length+' completed calls','v-purple')+
      kpi('Attempts',totalAttempts,'INVITEs sampled','v-blue')+
      kpi('Destinations',Object.keys(dsts).length,'unique carrier IPs','v-pink')+
      '</div>'+
      '<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Per-Destination Breakdown</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">ASR and ACD per carrier/destination IP. Click a row for full IP history.</div></div>'+
      '<table><thead><tr><th>Destination</th><th>Attempts</th><th>Answered</th><th>Failed</th><th>ASR</th><th>ACD</th><th>Fail codes</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  };
};

// ===== MESSAGES =====
pages['/messages']=function(params){
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">Messages</h1><p class="text-xs mt-0.5 mb-4" style="color:var(--z-muted)">SIP message search with filters and time ranges</p>'+
    '<div class="flex gap-2 mb-2 flex-wrap">'+
    '<input id="m-cid" placeholder="Call-ID (prefix with / for regex)" class="flex-1 min-w-[160px]">'+
    '<input id="m-method" placeholder="Method" class="w-24">'+
    '<input id="m-status" placeholder="Status" class="w-20">'+
    '<input id="m-ip" placeholder="IP address" class="w-32">'+
    '<select id="m-preset" onchange="applyPreset()" class="w-32"><option value="">Quick filters...</option><option value="errors">All Errors</option><option value="403">403 Forbidden</option><option value="404">404 Not Found</option><option value="486">486 Busy</option><option value="487">487 Cancelled</option><option value="500">500 Server Error</option><option value="503">503 Unavailable</option><option value="invite">INVITEs only</option><option value="register">REGISTERs only</option></select></div>'+
    '<div class="flex gap-2 mb-4 flex-wrap items-center">'+
    '<span class="text-[10px]" style="color:var(--z-dim)">Range:</span>'+
    '<select id="m-range" onchange="doSearch()" class="text-xs w-28"><option value="600000">Last 10 min</option><option value="1800000">Last 30 min</option><option value="3600000">Last 1 hour</option><option value="14400000">Last 4 hours</option><option value="86400000">Last 24 hours</option><option value="0">All time</option></select>'+
    '<button onclick="doSearch()" class="rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Search</button>'+
    '<button onclick="saveCurrentSearch()" class="rounded-md px-3 py-1.5 text-[10px] font-medium cursor-pointer" style="border:1px solid var(--z-line);color:var(--z-muted)">Save</button>'+
    '<span id="m-count" class="text-[10px] mono" style="color:var(--z-dim)"></span></div>'+
    '<div id="m-saved"></div>'+
    '<div id="m-table"><div class="card p-4 text-xs" style="color:var(--z-muted)">Loading recent messages...</div></div>';
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
    $('m-table').innerHTML='<div class="card p-4 text-sm text-[var(--z-muted)]">Searching...</div>';
    let msgs=await api('/api/messages'+q);
    // Client-side filter for "all errors" preset (status >= 400)
    if(preset==='errors'&&msgs){msgs=msgs.filter(m=>m.status>=400);}
    if(!msgs||!msgs.length){$('m-table').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-muted)">No messages found.</div>';$('m-count').textContent='0 results';return;}
    $('m-count').textContent=msgs.length+' results';
    let rows='';
    msgs.forEach(m=>{
      const st=m.status||0;
      const sc=st>=500?'text-[#ef4444]':st>=400?'text-[#fbbf24]':st>=300?'text-[#38bdf8]':st>=200?'text-[#34d399]':'';
      const mc=m.method&&m.method.includes('INVITE')?'text-[#f472b6]':'';
      rows+='<tr class="cursor-pointer hover:bg-[#131316]" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(m.call_id||'')+'\'"><td class="mono '+mc+'">'+h(m.method||'')+'</td><td class="mono '+sc+'">'+(st||'')+'</td><td class="mono text-[#a78bfa] truncate max-w-[180px]">'+h(m.call_id||'')+'</td><td class="mono">'+h(m.src||'')+'</td><td class="mono">'+h(m.dst||'')+'</td><td class="text-[var(--z-muted)]">'+agentHtml(m.agent)+'</td><td class="text-[var(--z-muted)]">'+(m.ts_ms?timeAgo(m.ts_ms):'')+'</td></tr>';
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
      links+='<div class="flex items-center gap-1"><button onclick="applySaved('+JSON.stringify(JSON.stringify(p)).replace(/"/g,'&quot;')+')" class="text-xs c-accent hover:underline cursor-pointer">'+h(s.name)+'</button>'+
        '<button onclick="deleteSaved('+s.id+')" class="text-[10px] cursor-pointer" style="color:var(--z-dim)">&times;</button></div>';
    });
    $('m-saved').innerHTML='<div class="flex flex-wrap gap-2 items-center mb-3"><span class="text-[10px]" style="color:var(--z-dim)">Saved:</span>'+links+'</div>';
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
  m.innerHTML='<div class="flex items-center gap-3 mb-5"><a href="#/calls" style="color:var(--z-muted)" class="text-sm hover:underline">&larr; Back</a><div><h1 class="text-lg font-semibold tracking-tight">Call Detail</h1><p class="text-xs mono mt-0.5 break-all" style="color:var(--z-muted)">'+h(cid)+'</p></div></div><div id="ld-content"><div class="card p-4 text-xs" style="color:var(--z-muted)">Loading call data...</div></div>';

  const msgs=await api('/api/messages?limit=500&call_id='+encodeURIComponent(cid));
  if(!msgs||!msgs.length){$('ld-content').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-muted)">No messages found for this call.</div>';return;}
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
  const statusColor=finalStatus.startsWith('Completed')?'v-green':finalStatus.startsWith('Failed')?'v-red':'v-yellow';
  const startTime=firstMsg.ts_ms?new Date(firstMsg.ts_ms):'';
  const startStr=startTime?startTime.toLocaleString():'';

  // Count request/response
  const reqCount=msgs.filter(m=>m.kind==='request').length;
  const respCount=msgs.filter(m=>m.kind==='response').length;

  let infoHtml='<div class="card p-5 mb-5"><div class="flex items-center justify-between mb-4"><div class="text-xs font-medium">Call Summary</div><div class="flex gap-2">'+
    '<button onclick="downloadBlob(buildPcap(window._ladderMsgs),\''+h(cid).substring(0,20)+'.pcap\')" class="rounded-md px-3 py-1.5 text-[10px] font-medium cursor-pointer flex items-center gap-1.5" style="border:1px solid var(--z-line);color:var(--z-muted)"><svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>PCAP</button>'+
    '<button onclick="exportJSON()" class="rounded-md px-3 py-1.5 text-[10px] font-medium cursor-pointer flex items-center gap-1.5" style="border:1px solid var(--z-line);color:var(--z-muted)"><svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>JSON</button>'+
    '<button onclick="navigator.clipboard.writeText(window.location.href)" class="rounded-md px-3 py-1.5 text-[10px] font-medium cursor-pointer flex items-center gap-1.5" style="border:1px solid var(--z-line);color:var(--z-muted)"><svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"/></svg>Copy link</button></div></div>'+
    '<div class="grid grid-cols-2 xl:grid-cols-4 gap-4 text-xs mb-3">'+
    '<div><div class="text-[10px]" style="color:var(--z-dim)">Status</div><div class="font-semibold mt-0.5 '+statusColor+'">'+finalStatus+'</div></div>'+
    '<div><div class="text-[10px]" style="color:var(--z-dim)">Duration</div><div class="mono font-semibold mt-0.5">'+durationSec+'s</div></div>'+
    '<div><div class="text-[10px]" style="color:var(--z-dim)">Messages</div><div class="mono mt-0.5">'+msgs.length+' <span style="color:var(--z-dim)">('+reqCount+' req, '+respCount+' resp)</span></div></div>'+
    '<div><div class="text-[10px]" style="color:var(--z-dim)">Server</div><div class="mt-0.5">'+agentHtml(firstMsg.agent)+'</div></div>'+
    '</div>'+
    '<div class="grid grid-cols-1 xl:grid-cols-2 gap-3 text-xs pt-3" style="border-top:1px solid var(--z-line)">'+
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
  const arrows={r:'var(--z-muted)',g:'#34d399',p:'#e879f9',y:'#facc15',e:'#f87171',b:'#38bdf8'};
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
    const color=isErr?'#f87171':isInv?'#e879f9':isBye||isCancel?'#facc15':is2xx?'#34d399':is3xx?'#38bdf8':is1xx?'var(--z-dim)':'var(--z-muted)';
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

  let ladderHtml='<div class="card mb-5"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="flex items-center justify-between"><div><div class="text-xs font-medium">SIP Ladder</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">'+msgs.length+' messages between '+epCount+' endpoints</div></div>'+
    '<div class="flex gap-3 text-[10px]" style="color:var(--z-dim)"><span><span style="color:#e879f9">━</span> INVITE</span><span><span style="color:#34d399">━</span> 2xx</span><span><span style="color:#facc15">━</span> BYE</span><span><span style="color:#f87171">━</span> Error</span><span><span style="color:var(--z-dim)">╌</span> 1xx</span></div></div></div>'+
    ladderCSS+'<div class="overflow-x-auto" style="background:var(--z-bg)">'+svg+'</div></div>';

  // ---- Message detail panel (shown on click) ----
  let detailHtml='<div id="msg-detail" class="card mb-5" style="display:none"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="flex items-center justify-between"><div class="text-xs font-medium">Message Detail</div><button onclick="$(\'msg-detail\').style.display=\'none\'" class="text-[10px] cursor-pointer" style="color:var(--z-dim)">&times; close</button></div></div><div id="msg-detail-content" class="p-4"></div></div>';

  // ---- Message list ----
  let msgRows='';
  msgs.forEach((msg,i)=>{
    const method=msg.method||'';
    const status=msg.status||0;
    const label=status>0?status+' '+method.replace(/^\d+ /,''):method;
    const isInv=method==='INVITE';
    const mc=isInv?'c-invite':status>=400?'v-red':status>=200&&status<300?'v-green':'';
    const delta=msg.ts_ms-t0;
    const ts=delta<1000?'+'+delta+'ms':'+'+(delta/1000).toFixed(1)+'s';
    msgRows+='<tr class="cursor-pointer" onclick="showMsgDetail('+i+')"><td class="text-[10px]" style="color:var(--z-dim)">'+(i+1)+'</td><td class="mono '+mc+'">'+h(label)+'</td><td class="mono text-[10px]">'+h(msg.src||'')+'</td><td style="color:var(--z-dim)">→</td><td class="mono text-[10px]">'+h(msg.dst||'')+'</td><td class="mono text-[10px]" style="color:var(--z-dim)">'+ts+'</td><td style="color:var(--z-muted)">'+(msg.ts_ms?new Date(msg.ts_ms).toLocaleTimeString():'')+'</td></tr>';
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
    if(body){detail+='<div class="mt-3"><div class="text-[10px] font-medium mb-1" style="color:var(--z-dim)">Body</div><pre class="mono text-[10px] p-2 rounded whitespace-pre-wrap" style="background:var(--z-bg);color:var(--z-muted)">'+h(body)+'</pre></div>';}
    detail+='</div>';
    // Right: raw SIP
    detail+='<div><div class="text-[10px] font-medium mb-1" style="color:var(--z-dim)">Raw SIP</div>'+
      '<pre class="mono text-[10px] p-3 rounded whitespace-pre-wrap break-all" style="background:var(--z-bg);color:var(--z-muted);max-height:400px;overflow-y:auto;line-height:1.5">'+h(raw)+'</pre></div>';
    detail+='</div>';

    $('msg-detail-content').innerHTML=detail;
    $('msg-detail').style.display='';
    $('msg-detail').scrollIntoView({behavior:'smooth',block:'nearest'});
  };

  window.toggleRaw=window.showMsgDetail;

  let msgsHtml='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Messages</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">Click any row to view full SIP headers and payload</div></div><table><thead><tr><th>#</th><th>Message</th><th>From</th><th></th><th>To</th><th>Delta</th><th>Time</th></tr></thead><tbody>'+msgRows+'</tbody></table></div>';

  // ---- QoS / Media panel ----
  const qos=await api('/api/qos?call_id='+encodeURIComponent(cid));
  let qosHtml='';
  if(qos&&qos.length>0){
    const q=qos[0];
    const mos=(n(q,'mos_x10')/10).toFixed(1);
    const mosColor=n(q,'mos_x10')>=40?'v-green':n(q,'mos_x10')>=30?'v-yellow':'v-red';
    qosHtml='<div class="card p-5 mb-5"><div class="text-xs font-medium mb-3">Call Quality (RTCP)</div>'+
      '<div class="grid grid-cols-2 xl:grid-cols-5 gap-3">'+
      kpi('MOS',mos,'voice quality',mosColor)+
      kpi('Jitter',n(q,'jitter_ms')+'ms','max jitter','v-blue')+
      kpi('Loss',n(q,'loss_pct')+'%','max packet loss',n(q,'loss_pct')>2?'v-red':'v-green')+
      kpi('R-Factor',n(q,'r_factor'),'ITU-T G.107','v-purple')+
      kpi('Codec',q.codec||'—','media codec','v-blue')+
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
        mediaHtml='<div class="card p-5 mb-5"><div class="text-xs font-medium mb-3">Media</div>'+
          '<div class="grid grid-cols-3 gap-4 text-xs">'+
          '<div><span style="color:var(--z-dim)">Codecs:</span> <span class="mono">'+h(codecs.join(', ')||'—')+'</span></div>'+
          '<div><span style="color:var(--z-dim)">Media port:</span> <span class="mono">'+(mediaPort||'—')+'</span></div>'+
          '<div><span style="color:var(--z-dim)">Security:</span> '+(srtp?'<span class="v-green font-medium">SRTP (encrypted)</span>':'<span style="color:var(--z-muted)">RTP (unencrypted)</span>')+'</div>'+
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
      rRows+='<a href="#/ladder?call_id='+encodeURIComponent(r.call_id||'')+'" class="flex items-center gap-2 px-4 py-2 text-xs hover:underline c-accent mono" style="border-bottom:1px solid var(--z-line)">'+h(r.call_id)+' <span class="text-[10px]" style="color:var(--z-dim)">('+h(r.reason||'correlated')+')</span></a>';
    });
    relatedHtml='<div class="card mb-5"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Related Call Legs</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">B2BUA correlated calls — click to view</div></div>'+rRows+'</div>';
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
      if(badge) badge.innerHTML='<span class="text-[10px] v-green mono">● live · '+fresh.length+' messages</span>';
    };
    // Add live badge to the ladder header
    const ladderHeader=document.querySelector('#ld-content .card .text-xs.font-medium');
    if(ladderHeader){
      ladderHeader.insertAdjacentHTML('afterend',' <span id="ld-live-badge" class="ml-2"><span class="text-[10px] v-green mono">● live</span></span>');
    }
    intervals.push(setInterval(refreshLadder,5000));
  }
};

// ===== NOC =====
pages['/noc']=function(){
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">NOC</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Node health and server status. Click a name to rename.</p><div id="noc-t"></div>';
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
    if(!nodes||!nodes.length){$('noc-t').innerHTML='<div class="card p-4 text-sm text-[var(--z-muted)]">No nodes reporting.</div>';return;}
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
      const sc=s==='green'?'#34d399':s==='yellow'?'#fbbf24':'#ef4444';
      const displayName=window._nodeNames[agent]||'';
      const nameHtml=displayName
        ?'<span class="font-medium">'+h(displayName)+'</span> <span class="text-[10px]" style="color:var(--z-muted)">('+h(agent)+')</span>'
        :'<span class="font-medium">'+h(agent)+'</span>';
      const ips=ipMap[agent]?Array.from(ipMap[agent]).sort().join(', '):'';
      rows+='<tr>'+
        '<td><div class="flex items-center gap-2 cursor-pointer" onclick="renameNode(\''+agent+'\')"><span class="w-2 h-2 rounded-full '+dot+' shrink-0"></span><div>'+nameHtml+'</div></div></td>'+
        '<td class="mono text-[11px]" style="color:var(--z-muted)">'+h(ips)+'</td>'+
        '<td style="color:'+sc+'">'+sl+'</td>'+
        '<td class="mono">'+n(nd,'total')+'</td>'+
        '<td class="mono">'+n(nd,'active_calls')+'</td>'+
        '<td class="mono">'+n(nd,'calls')+'</td>'+
        '<td class="mono">'+(n(nd,'errors')>0?'<span style="color:#ef4444">'+n(nd,'errors')+'</span>':n(nd,'errors'))+'</td>'+
        '<td class="text-[var(--z-muted)]">'+n(nd,'age_sec')+'s ago</td></tr>';
    });
    $('noc-t').innerHTML='<div class="card"><table><thead><tr><th>Server</th><th>IPs</th><th>Status</th><th>Total 5m</th><th>Active Calls</th><th>Call IDs</th><th>Errors</th><th>Last Seen</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  },5000);
};

// ===== METRICS =====
pages['/metrics']=function(){
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">Metrics</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Protocol counters, ingest health, and traffic trends</p>'+
    '<div id="met-kpi"></div>'+
    '<div class="grid xl:grid-cols-2 gap-5 mt-5"><div class="card p-4"><div class="text-xs font-medium mb-3">CPS Over Time</div><div style="height:200px"><canvas id="met-cps-chart"></canvas></div></div>'+
    '<div id="met-codes"></div></div>'+
    '<div class="mt-5" id="met-hep"></div>';

  Promise.all([api('/api/metrics'),api('/api/report/cps?minutes=60'),api('/api/report/response-codes')]).then(([s,cps,codes])=>{
    if(s){
      let html='<div class="grid grid-cols-2 xl:grid-cols-4 gap-3">';
      [['Messages',s.msgs_total||0,'total captured','v-blue'],
       ['Requests',s.requests||0,'SIP requests','v-green'],
       ['Responses',s.responses||0,'SIP responses','v-purple'],
       ['DB Writes',s.db_ok||0,'successful','v-green'],
       ['DB Errors',s.db_err||0,'failed',s.db_err>0?'v-red':'v-green'],
       ['DB Drops',s.db_drop||0,'channel full',s.db_drop>0?'v-red':'v-green'],
       ['Echoes',s.echoes||0,'SIP replies sent','v-blue'],
       ['Uptime',(Math.floor((s.uptime_ms||0)/3600000))+'h','service uptime','v-purple']
      ].forEach(([l,v,sub,c])=>{html+=kpi(l,typeof v==='number'?v.toLocaleString():v,sub,c);});
      html+='</div>';
      $('met-kpi').innerHTML=html;

      // HEP breakdown
      let hepHtml='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">HEP Protocol Breakdown</div></div><div class="grid grid-cols-2 xl:grid-cols-4 gap-3 p-4">';
      [['HEP Total',s.hep_total,'v-purple'],['SIP',s.hep_sip,'v-pink'],['RTCP',s.hep_rtcp,'v-green'],['RTP',s.hep_rtp,'v-blue'],
       ['RTCP-XR',s.hep_rtcpxr,'v-yellow'],['UDP',s.hep_udp,'v-blue'],['TCP',s.hep_tcp,'v-purple'],['TLS',s.hep_tls,'v-green']
      ].forEach(([l,v,c])=>{hepHtml+=kpi(l,(v||0).toLocaleString(),'',c);});
      hepHtml+='</div></div>';
      $('met-hep').innerHTML=hepHtml;
    }

    // CPS chart
    if(cps&&cps.length>1){
      const labels=cps.map(c=>{const d=new Date(c.minute*60000);return d.toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit'});});
      const totals=cps.map(c=>c.total);
      const invites=cps.map(c=>c.invites);
      const ctx=$('met-cps-chart');
      if(ctx) new Chart(ctx,{type:'line',data:{labels,datasets:[{label:'Total msgs/min',data:totals,borderColor:'#38bdf8',backgroundColor:'rgba(56,189,248,0.06)',borderWidth:1.5,pointRadius:0,fill:true,tension:0.3},{label:'INVITEs/min',data:invites,borderColor:'#e879f9',borderWidth:1.5,pointRadius:0,fill:false,tension:0.3}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:0},plugins:{legend:{position:'bottom',labels:{boxWidth:8,font:{size:10},color:'#71717a'}}},scales:{x:{ticks:{maxTicksToLimit:10,font:{size:9},color:'#52525b'},grid:{display:false}},y:{beginAtZero:true,ticks:{font:{size:9},color:'#52525b'},grid:{color:'rgba(128,128,128,0.08)'}}}}});
    }

    // Response codes
    if(codes&&codes.length){
      let rows='';
      const maxC=Math.max(...codes.map(c=>c.count||0))||1;
      codes.forEach(c=>{
        const st=c.status||0;
        const sc=st>=500?'v-red':st>=400?'v-yellow':st>=300?'v-blue':st>=200?'v-green':'';
        rows+='<tr><td class="mono '+sc+'">'+st+'</td><td>'+h(c.reason||'')+'</td><td class="mono">'+n(c,'count').toLocaleString()+'</td>'+
          '<td><div class="w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full" style="width:'+((c.count||0)/maxC*100).toFixed(0)+'%;background:var(--z-muted)"></div></div></td></tr>';
      });
      $('met-codes').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Response Codes</div></div><table><thead><tr><th>Code</th><th>Reason</th><th>Count</th><th>Volume</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }
  });
};

// ===== REPORTS =====
pages['/reports']=function(){
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">Reports</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Telecom KPIs, traffic analysis, top endpoints, and per-server breakdown.</p>'+
    '<div id="rep-kpi">Loading KPIs...</div>'+
    '<div class="grid xl:grid-cols-2 gap-5 mt-5"><div class="card p-4"><div class="text-xs font-medium mb-3">ASR / ACD Trend (24h)</div><div style="height:180px"><canvas id="rep-trend-chart"></canvas></div></div>'+
    '<div class="card p-4"><div class="text-xs font-medium mb-3">Call Volume (24h)</div><div style="height:180px"><canvas id="rep-vol-chart"></canvas></div></div></div>'+
    '<div class="grid xl:grid-cols-2 gap-5 mt-5"><div id="rep-agents"></div><div id="rep-talkers"></div></div>'+
    '<div class="grid xl:grid-cols-2 gap-5 mt-5"><div id="rep-methods"></div><div id="rep-topcalls"></div></div>'+
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
      const asr=n(rt,'asr'),ner=n(rt,'ner'),errRate=n(rt,'err_rate');
      const fails=n(rt,'resp_4xx')+n(rt,'resp_5xx');
      $('rep-kpi').innerHTML='<div class="grid grid-cols-2 xl:grid-cols-4 gap-3">'+
        kpi('Concurrent Calls',n(rt,'active_calls'),'open dialogs','v-pink')+
        kpi('CPS',perSec(n(rt,'invites'),60),'calls/sec this minute','v-green')+
        kpi('Message Rate',perSec(n(rt,'total'),60)+'/s','all captures/sec','v-blue')+
        kpi('Call Attempts',n(rt,'invites'),'INVITEs in 1m','v-yellow')+
        kpi('Answered',n(rt,'answered_calls'),'completed calls','v-green')+
        kpi('Failed',n(rt,'failed_calls'),'4xx/5xx responses','v-red')+
        kpi('ASR',asr+'%','answer seizure ratio',asr>=70?'v-green':asr>=40?'v-yellow':'v-red')+
        kpi('NER',ner+'%','network effectiveness',ner>=90?'v-green':'v-yellow')+
        kpi('ACD',n(rt,'acd_seconds')+'s','avg call duration','v-purple')+
        kpi('Error Rate',errRate+'%','error/total ratio',errRate<=5?'v-green':'v-red')+
        kpi('Registers',n(rt,'registers'),'REG in 1m','v-blue')+
        kpi('Sources',n(rt,'sources'),'unique IPs','v-purple')+
        '</div>';
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
          '<td><div class="flex items-center gap-2"><div class="flex-1 rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full bg-[#a78bfa]" style="width:'+pct+'%"></div></div><span class="mono text-[10px]" style="color:var(--z-muted)">'+pct+'%</span></div></td>'+
          '<td class="text-[var(--z-muted)]">'+(a.last_seen?timeAgo(a.last_seen):'')+'</td></tr>';
      });
      $('rep-agents').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium" style="color:var(--z-ink)">Traffic by Server</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">Message and call distribution across HEP agents.</div></div><table><thead><tr><th>Server</th><th>Messages</th><th>Call IDs</th><th>Share</th><th>Last Seen</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
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
          '<td class="mono text-[10px]" style="color:var(--z-muted)">'+(i+1)+'</td>'+
          '<td class="mono text-[#a78bfa]">'+h(t.src||'')+'</td>'+
          '<td class="mono">'+msgs.toLocaleString()+'</td>'+
          '<td class="mono">'+n(t,'calls').toLocaleString()+'</td>'+
          '<td><div class="w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full bg-[#38bdf8]" style="width:'+pct+'%"></div></div></td></tr>';
      });
      $('rep-talkers').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium" style="color:var(--z-ink)">Top Endpoints</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">Busiest source IPs. Click to view IP history.</div></div><table><thead><tr><th>#</th><th>Endpoint</th><th>Msgs</th><th>Calls</th><th>Volume</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
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
        const color=m==='INVITE'?'#f472b6':m==='BYE'?'#fbbf24':m==='REGISTER'?'#38bdf8':m==='OPTIONS'?'#71717a':'#a78bfa';
        mRows+='<tr><td class="font-medium" style="color:'+color+'">'+h(m)+'</td><td class="mono">'+c.toLocaleString()+'</td><td class="mono text-[10px]" style="color:var(--z-muted)">'+pct+'%</td>'+
          '<td><div class="w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full" style="background:'+color+';width:'+pct+'%"></div></div></td></tr>';
      });
      // Response code summary
      const rTotal=Object.values(responses).reduce((s,v)=>s+v,0)||1;
      let rRows='';
      [['2xx','#34d399'],['3xx','#38bdf8'],['4xx','#fbbf24'],['5xx','#ef4444']].forEach(([code,color])=>{
        const c=responses[code];
        if(c>0){
          rRows+='<tr><td class="mono font-medium" style="color:'+color+'">'+code+'</td><td class="mono">'+c.toLocaleString()+'</td><td class="mono text-[10px]" style="color:var(--z-muted)">'+(c/rTotal*100).toFixed(1)+'%</td>'+
            '<td><div class="w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full" style="background:'+color+';width:'+(c/rTotal*100).toFixed(0)+'%"></div></div></td></tr>';
        }
      });
      $('rep-methods').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium" style="color:var(--z-ink)">Request Methods</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">'+n(summary,'total').toLocaleString()+' total messages · '+n(summary,'unique_call_ids').toLocaleString()+' unique Call-IDs</div></div><table><thead><tr><th>Method</th><th>Count</th><th>%</th><th>Volume</th></tr></thead><tbody>'+mRows+'</tbody></table>'+
        (rRows?'<div class="p-4 pt-3" style="border-top:1px solid var(--z-line)"><div class="section-title mb-2">Response Codes</div><table><thead><tr><th>Class</th><th>Count</th><th>%</th><th>Volume</th></tr></thead><tbody>'+rRows+'</tbody></table></div>':'')+
        '</div>';
    }

    // Top calls
    if(topCalls&&topCalls.length){
      let rows='';
      topCalls.forEach(c=>{
        const st=c.state==='active'?'<span class="text-[#34d399]">active</span>':'<span style="color:var(--z-muted)">'+h(c.state||'')+'</span>';
        const from=(c.from||'').replace(/<[^>]*>/g,'').replace(/;.*/,'').trim()||'-';
        const to=(c.to||'').replace(/<[^>]*>/g,'').replace(/;.*/,'').trim()||'-';
        rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(c.call_id||'')+'\'">'+
          '<td class="mono text-[#a78bfa] truncate max-w-[200px]">'+h(c.call_id||'')+'</td>'+
          '<td class="mono">'+n(c,'messages')+'</td>'+
          '<td>'+st+'</td>'+
          '<td class="truncate max-w-[150px]">'+h(from)+'</td>'+
          '<td class="truncate max-w-[150px]">'+h(to)+'</td>'+
          '<td class="text-[var(--z-muted)]">'+(c.ts_first?timeAgo(c.ts_first):'')+'</td></tr>';
      });
      $('rep-topcalls').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium" style="color:var(--z-ink)">Top Calls by Messages</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">Calls with the most SIP messages. Click for ladder.</div></div><table><thead><tr><th>Call-ID</th><th>Msgs</th><th>State</th><th>From</th><th>To</th><th>Started</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }

    // Overall summary stats
    if(summary){
      const span=n(summary,'ts_max')-n(summary,'ts_min');
      const hours=(span/3600000).toFixed(1);
      $('rep-daily').innerHTML='<div class="card p-5"><div class="flex flex-wrap gap-6 text-xs">'+
        '<div><span style="color:var(--z-muted)">Total messages:</span> <span class="mono font-medium">'+n(summary,'total').toLocaleString()+'</span></div>'+
        '<div><span style="color:var(--z-muted)">Unique Call-IDs:</span> <span class="mono font-medium">'+n(summary,'unique_call_ids').toLocaleString()+'</span></div>'+
        '<div><span style="color:var(--z-muted)">HEP captured:</span> <span class="mono font-medium">'+n(summary,'hep').toLocaleString()+'</span></div>'+
        '<div><span style="color:var(--z-muted)">Time span:</span> <span class="mono font-medium">'+hours+' hours</span></div>'+
        '<div><span style="color:var(--z-muted)">Avg msgs/sec:</span> <span class="mono font-medium">'+perSec(n(summary,'total'),span/1000)+'</span></div>'+
        '</div></div>';
    }

    // Historical trend charts
    if(hourly&&hourly.length>1){
      const chartOpts={responsive:true,maintainAspectRatio:false,animation:{duration:0},plugins:{legend:{position:'bottom',labels:{boxWidth:8,font:{size:10},color:'#71717a'}}},scales:{x:{ticks:{maxTicksToLimit:12,font:{size:9},color:'#52525b'},grid:{display:false}},y:{beginAtZero:true,ticks:{font:{size:9},color:'#52525b'},grid:{color:'rgba(128,128,128,0.08)'}}}};
      const labels=hourly.map(h=>{const d=new Date(h.ts);return d.toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit'});});

      // ASR/ACD trend
      const tc=$('rep-trend-chart');
      if(tc){
        const asrData=hourly.map(h=>h.asr);
        const acdData=hourly.map(h=>h.acd);
        new Chart(tc,{type:'line',data:{labels,datasets:[
          {label:'ASR %',data:asrData,borderColor:'#34d399',borderWidth:1.5,pointRadius:0,fill:false,tension:0.3,yAxisID:'y'},
          {label:'ACD (s)',data:acdData,borderColor:'#a78bfa',borderWidth:1.5,pointRadius:0,fill:false,tension:0.3,yAxisID:'y1'}
        ]},options:{...chartOpts,scales:{...chartOpts.scales,y:{...chartOpts.scales.y,position:'left',title:{display:true,text:'ASR %',font:{size:9},color:'#52525b'}},y1:{position:'right',beginAtZero:true,ticks:{font:{size:9},color:'#52525b'},grid:{display:false},title:{display:true,text:'ACD (s)',font:{size:9},color:'#52525b'}}}}});
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
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">SLA</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Service level monitoring. Targets are configurable — click a gauge to learn more.</p>'+
    '<div id="sla-summary"></div>'+
    '<div class="grid xl:grid-cols-2 gap-5 mt-5"><div id="sla-agents"></div><div id="sla-errors"></div></div>'+
    '<div class="grid xl:grid-cols-2 gap-5 mt-5"><div id="sla-dests"></div><div id="sla-srcs"></div></div>';

  // SLA targets — stored in localStorage
  const defaults={asr:70,ner:90,err_rate:5,acd_min:30};
  function targets(){try{return{...defaults,...JSON.parse(localStorage.getItem('zaman_sla_targets')||'{}')};}catch(e){return defaults;}}
  function saveTargets(t){localStorage.setItem('zaman_sla_targets',JSON.stringify(t));}

  function gauge(label,value,unit,target,invert){
    // invert: true means lower is better (err_rate)
    const met=invert?(value<=target):(value>=target);
    const warn=invert?(value<=target*1.5):(value>=target*0.7);
    const color=met?'#34d399':warn?'#fbbf24':'#ef4444';
    const status=met?'MET':warn?'AT RISK':'BREACHED';
    const statusColor=met?'text-[#34d399]':warn?'text-[#fbbf24]':'text-[#ef4444]';
    return '<div class="card p-5 cursor-pointer" onclick="editTarget(\''+label+'\')">'+
      '<div class="flex items-center justify-between mb-3"><div class="text-[10px] uppercase tracking-wider font-semibold" style="color:var(--z-dim)">'+h(label)+'</div><span class="text-[10px] font-semibold '+statusColor+'">'+status+'</span></div>'+
      '<div class="text-3xl font-bold mono" style="color:'+color+'">'+value+unit+'</div>'+
      '<div class="mt-2 w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full" style="background:'+color+';width:'+Math.min(100,invert?Math.max(0,(1-value/Math.max(target*2,1))*100):Math.min(100,value/Math.max(target,1)*100))+'%"></div></div>'+
      '<div class="flex justify-between mt-1.5 text-[10px]" style="color:var(--z-muted)"><span>target: '+(invert?'≤':'≥')+target+unit+'</span><span>current</span></div></div>';
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
        kpi('Concurrent Calls',active,'open dialogs','v-pink')+
        kpi('Invites 5m',invites,'call attempts','v-blue')+
        kpi('Answered',answered,'completed calls','v-green')+
        kpi('Failed',failed,'4xx/5xx','v-red')+
        kpi('Sources',n(rt1,'sources'),'unique IPs','v-purple')+
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
        const asrColor=asr>=t.asr?'#34d399':asr>=t.asr*0.7?'#fbbf24':'#ef4444';
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
      $('sla-agents').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium" style="color:var(--z-ink)">Per-Server SLA (5 min)</div></div><table><thead><tr><th>Server</th><th>Total</th><th>Invites</th><th>Answered</th><th>Failed</th><th>ASR</th><th>ACD</th><th>Active</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }

    // Error breakdown
    if(rt5){
      const codes=[
        {label:'401 Unauthorized',val:n(rt5,'err_401'),color:'#fbbf24'},
        {label:'403 Forbidden',val:n(rt5,'err_403'),color:'#f97316'},
        {label:'404 Not Found',val:n(rt5,'err_404'),color:'#a78bfa'},
        {label:'486 Busy',val:n(rt5,'err_486'),color:'#38bdf8'},
        {label:'503 Unavailable',val:n(rt5,'err_503'),color:'#ef4444'},
        {label:'Other 4xx',val:n(rt5,'resp_4xx')-n(rt5,'err_401')-n(rt5,'err_403')-n(rt5,'err_404')-n(rt5,'err_486'),color:'#71717a'},
        {label:'5xx',val:n(rt5,'resp_5xx')-n(rt5,'err_503'),color:'#dc2626'},
      ].filter(c=>c.val>0);
      const total=codes.reduce((s,c)=>s+c.val,0)||1;
      let bars='';
      codes.forEach(c=>{
        const pct=(c.val/total*100).toFixed(1);
        bars+='<div class="flex items-center gap-3 py-2" style="border-bottom:1px solid var(--z-line)"><div class="w-28 text-xs">'+c.label+'</div><div class="flex-1"><div class="w-full rounded-full h-2" style="background:var(--z-line)"><div class="h-2 rounded-full" style="background:'+c.color+';width:'+pct+'%"></div></div></div><div class="mono text-xs w-16 text-right">'+c.val+'</div><div class="text-[10px] w-12 text-right" style="color:var(--z-muted)">'+pct+'%</div></div>';
      });
      if(!bars) bars='<div class="py-4 text-sm" style="color:var(--z-muted)">No errors in the last 5 minutes.</div>';
      $('sla-errors').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium" style="color:var(--z-ink)">Error Breakdown (5 min)</div></div><div class="p-4">'+bars+'</div></div>';
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
        const asrColor=asr>=70?'v-green':asr>=40?'v-yellow':'v-red';
        rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ip?addr='+encodeURIComponent(ip)+'\'">'+
          '<td class="mono c-accent">'+h(ip)+'</td>'+
          '<td class="mono">'+n(d,'invites')+'</td>'+
          '<td class="mono v-green">'+n(d,'ok_2xx')+'</td>'+
          '<td class="mono '+(n(d,'errors')>0?'v-red':'')+'">'+n(d,'errors')+'</td>'+
          '<td class="mono '+asrColor+'">'+asr+'%</td>'+
          '<td class="mono">'+acd+'s</td></tr>';
      });
      $(elId).innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">'+label+'</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">ASR and ACD per IP (5 min window). Click to view history.</div></div><table><thead><tr><th>IP</th><th>Attempts</th><th>Answered</th><th>Failed</th><th>ASR</th><th>ACD</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }
    ipTable(dests,'Destination IPs (Carriers)','dst','sla-dests');
    ipTable(srcs,'Source IPs (Origins)','src','sla-srcs');
  }
  poll(refreshSLA,5000);
};

// ===== ALERTS =====
pages['/alerts']=function(){
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">Alerts</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Live anomaly detection from the last 5 minutes</p>'+
    '<div id="al-status"></div><div class="mt-5" id="al-codes"></div>';
  async function refreshAlerts(){
    const [anomalies,codes]=await Promise.all([api('/api/anomalies'),api('/api/report/response-codes')]);
    if(anomalies&&anomalies.length){
      let rows='';
      anomalies.forEach(a=>{
        const sev=a.severity==='critical'?'v-red':'v-yellow';
        const icon=a.severity==='critical'?'&#x26A0;':'&#x26A0;';
        rows+='<div class="flex items-center gap-3 p-3" style="border-bottom:1px solid var(--z-line)">'+
          '<span class="'+sev+'">'+icon+'</span>'+
          '<div class="flex-1"><div class="text-xs font-medium">'+h(a.message||a.type)+'</div><div class="text-[10px]" style="color:var(--z-muted)">'+h(a.type)+' · '+n(a,'count')+' occurrences</div></div>'+
          '<span class="text-[10px] font-medium '+sev+'">'+h(a.severity)+'</span></div>';
      });
      $('al-status').innerHTML='<div class="card">'+rows+'</div>';
    } else {
      $('al-status').innerHTML='<div class="card p-5 text-center"><div class="v-green text-lg mb-1">&#x2714;</div><div class="text-xs font-medium">No anomalies detected</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">All metrics within normal thresholds</div></div>';
    }
    if(codes&&codes.length){
      let rows='';
      const maxCnt=Math.max(...codes.map(c=>c.count||0))||1;
      codes.forEach(c=>{
        const st=c.status||0;
        const color=st>=500?'v-red':st>=400?'v-yellow':st>=300?'v-blue':st>=200?'v-green':'';
        const pct=((c.count||0)/maxCnt*100).toFixed(0);
        rows+='<tr><td class="mono '+color+'">'+st+'</td><td>'+h(c.reason||'')+'</td><td class="mono">'+n(c,'count').toLocaleString()+'</td>'+
          '<td><div class="w-full rounded-full h-1.5" style="background:var(--z-line)"><div class="h-1.5 rounded-full" style="width:'+pct+'%;background:var(--z-muted)"></div></div></td></tr>';
      });
      $('al-codes').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Response Code Distribution</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">From recent 50K messages</div></div><table><thead><tr><th>Code</th><th>Reason</th><th>Count</th><th>Volume</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    }
  }
  refreshAlerts();
  poll(refreshAlerts,10000);

  // Load alert config
  fetch('/api/alerts/config',{headers:headers()}).then(r=>r.ok?r.json():null).then(cfg=>{
    if(!cfg)return;
    const webhooks=(cfg.webhooks||[]).join('\n');
    $('al-codes').insertAdjacentHTML('afterend',
      '<div class="card p-5 mt-5"><div class="text-xs font-medium mb-3">Alert Configuration</div>'+
      '<div class="grid xl:grid-cols-2 gap-4">'+
      '<div><label class="text-[10px] font-medium" style="color:var(--z-dim)">Webhook URLs (one per line)</label>'+
      '<textarea id="al-webhooks" rows="3" class="w-full mt-1 rounded-md text-xs mono p-2" style="background:var(--z-field);border:1px solid var(--z-line);color:var(--z-ink);resize:vertical">'+h(webhooks)+'</textarea></div>'+
      '<div><label class="text-[10px] font-medium" style="color:var(--z-dim)">Thresholds</label>'+
      '<div class="grid grid-cols-2 gap-2 mt-1">'+
      '<div><span class="text-[10px]" style="color:var(--z-dim)">Min ASR %</span><input id="al-asr" type="number" value="'+(cfg.thresholds?.asr_min||70)+'" class="w-full mt-0.5 text-xs"></div>'+
      '<div><span class="text-[10px]" style="color:var(--z-dim)">Max Error Rate %</span><input id="al-err" type="number" value="'+(cfg.thresholds?.err_rate_max||10)+'" class="w-full mt-0.5 text-xs"></div></div>'+
      '<button onclick="saveAlertConfig()" class="mt-3 rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Save</button></div></div></div>');
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
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">Call Quality</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Aggregate QoS from RTCP data.</p><div id="qos-c"></div>';
  $('qos-c').innerHTML='<div class="card p-4 text-sm text-[var(--z-muted)]">No RTCP data available yet. Configure your media server to send HEP type 5 (RTCP) to zaman on port 9060.</div>';
};

// ===== IP =====
pages['/ip']=function(params){
  const preIP=params?params.get('addr')||'':'';
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">IP History</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Traffic analysis for a specific endpoint</p>'+
    '<div class="flex gap-2 mb-5"><input id="ip-addr" placeholder="Enter an IP address (e.g. 44.196.20.220)" value="'+h(preIP)+'" class="flex-1">'+
    '<button onclick="ipLookup()" class="rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Search</button></div>'+
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
          '<td class="mono text-[10px]" style="color:var(--z-dim)">'+(i+1)+'</td>'+
          '<td class="mono c-accent">'+h(t.src||'')+'</td>'+
          '<td class="mono">'+n(t,'messages').toLocaleString()+'</td>'+
          '<td class="mono">'+n(t,'calls').toLocaleString()+'</td>'+
          '</tr>';
      });
      $('ip-top').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Top Endpoints</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">Click an IP to view its traffic history.</div></div><table><thead><tr><th>#</th><th>Endpoint</th><th>Messages</th><th>Calls</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
    });
  }

  $('ip-addr').addEventListener('keydown',e=>{if(e.key==='Enter')ipLookup();});

  window.ipLookup=async function(){
    const ip=$('ip-addr').value.trim();
    if(!ip) return;
    $('ip-top').innerHTML='';
    $('ip-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-muted)">Searching...</div>';
    $('ip-summary').innerHTML='';

    const msgs=await api('/api/messages?limit=300&ip='+encodeURIComponent(ip));
    if(!msgs||!msgs.length){$('ip-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-muted)">No messages found for '+h(ip)+'.</div>';return;}

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
      kpi('ASR',asr+'%','answered / '+invites+' INVITEs',asr>=70?'v-green':asr>=40?'v-yellow':'v-red')+
      kpi('ACD',acd+'s',durations.length+' completed calls','v-purple')+
      kpi('Answered',answered,'of '+invites+' attempts','v-green')+
      kpi('Failed',failed,failList||'no failures',failed>0?'v-red':'v-green')+
      '</div>'+
      '<div class="grid grid-cols-2 xl:grid-cols-5 gap-3 mb-4">'+
      kpi('Messages',msgs.length,'in sample','v-blue')+
      kpi('Call IDs',callIds.size,'unique calls','v-purple')+
      kpi('As source',asSrc,'outbound','v-green')+
      kpi('As dest',asDst,'inbound','v-yellow')+
      kpi('Peers',peers.size,'unique endpoints','v-pink')+
      '</div>'+
      '<div class="card p-3 px-4 mb-4 text-[10px] mono" style="color:var(--z-muted)">'+methodList+'</div>';

    // GeoIP + carrier scorecard (async, non-blocking)
    Promise.all([api('/api/geoip?ip='+encodeURIComponent(ip)),api('/api/sla/carrier?ip='+encodeURIComponent(ip))]).then(([geo,carrier])=>{
      // GeoIP card with map
      if(geo&&geo.status==='success'){
        let geoHtml='<div class="card"><div class="grid xl:grid-cols-[1fr_300px]"><div class="p-4"><div class="text-xs font-medium mb-3">Location</div>'+
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
          L.circleMarker([geo.lat,geo.lon],{radius:8,color:'#a78bfa',fillColor:'#a78bfa',fillOpacity:0.6,weight:2}).addTo(map).bindPopup(h(ip)+' · '+h(geo.city||'')+', '+h(geo.country||''));
        }
      }
      // Carrier scorecard with trend chart
      if(carrier&&carrier.invites>0){
        let cHtml='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Carrier Scorecard (60 min)</div></div>'+
          '<div class="grid grid-cols-2 xl:grid-cols-5 gap-3 p-4">'+
          kpi('ASR',carrier.asr+'%','answer rate',carrier.asr>=70?'v-green':carrier.asr>=40?'v-yellow':'v-red')+
          kpi('ACD',carrier.acd+'s','avg duration','v-purple')+
          kpi('Attempts',carrier.invites,'INVITEs','v-blue')+
          kpi('Answered',carrier.ok_2xx,'completed','v-green')+
          kpi('Failed',carrier.errors,'rejected',carrier.errors>0?'v-red':'v-green')+
          '</div>';
        // Error code breakdown
        if(carrier.error_codes&&Object.keys(carrier.error_codes).length){
          let codes='';
          Object.entries(carrier.error_codes).sort((a,b)=>b[1]-a[1]).forEach(([c,n])=>{
            codes+='<span class="mono text-xs v-yellow">'+c+': '+n+'</span> ';
          });
          cHtml+='<div class="px-4 pb-3 text-[10px]" style="color:var(--z-dim)">Failure codes: '+codes+'</div>';
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
          if(ctx)new Chart(ctx,{type:'line',data:{labels,datasets:[{label:'Attempts',data:invD,borderColor:'#38bdf8',borderWidth:1.5,pointRadius:0,fill:false,tension:0.3},{label:'Answered',data:ansD,borderColor:'#34d399',backgroundColor:'rgba(52,211,153,0.06)',borderWidth:1.5,pointRadius:0,fill:true,tension:0.3}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:0},plugins:{legend:{position:'bottom',labels:{boxWidth:8,font:{size:10},color:'#71717a'}}},scales:{x:{ticks:{maxTicksToLimit:8,font:{size:9},color:'#52525b'},grid:{display:false}},y:{beginAtZero:true,ticks:{font:{size:9},color:'#52525b'},grid:{color:'rgba(128,128,128,0.08)'}}}}});
        }
      }
    });

    // Message table
    let rows='';
    msgs.forEach(m=>{
      const st=m.status||0;
      const sc=st>=500?'v-red':st>=400?'v-yellow':st>=200?'v-green':'';
      const mc=m.method==='INVITE'?'c-invite':m.method==='BYE'?'c-bye':'';
      rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(m.call_id||'')+'\'">'+
        '<td class="mono '+mc+'">'+h(m.method||'')+'</td>'+
        '<td class="mono '+sc+'">'+(st||'')+'</td>'+
        '<td class="mono c-accent truncate max-w-[180px]">'+h(m.call_id||'')+'</td>'+
        '<td class="mono">'+h(m.src||'')+'</td>'+
        '<td class="mono">'+h(m.dst||'')+'</td>'+
        '<td>'+agentHtml(m.agent)+'</td>'+
        '<td style="color:var(--z-muted)">'+(m.ts_ms?timeAgo(m.ts_ms):'')+'</td></tr>';
    });
    $('ip-r').innerHTML='<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Traffic for '+h(ip)+'</div><div class="text-[10px] mt-1" style="color:var(--z-muted)">'+msgs.length+' messages · '+callIds.size+' calls · '+peers.size+' peers</div></div><table><thead><tr><th>Method</th><th>Code</th><th>Call-ID</th><th>Source</th><th>Destination</th><th>Server</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  };
  if(preIP) ipLookup();
};

// ===== PROBE =====
pages['/probe']=function(){
  window._probeHistory=window._probeHistory||[];
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">SIP Probe</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Send SIP OPTIONS to test endpoint reachability and measure RTT</p>'+
    '<div class="card p-5 mb-5"><div class="flex gap-2 mb-2 flex-wrap"><input id="pr-host" placeholder="Hostname or IP" class="flex-1 min-w-[200px]"><input id="pr-port" placeholder="5060" class="w-24">'+
    '<button onclick="doProbe()" class="rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Probe</button></div>'+
    '<div class="text-[10px]" style="color:var(--z-dim)">Sends SIP OPTIONS and waits for a response. Requires ZAMAN_PROBE=1 on the core.</div></div>'+
    '<div id="pr-r"></div><div id="pr-history"></div>';
  $('pr-host').addEventListener('keydown',e=>{if(e.key==='Enter')doProbe();});
  function renderHistory(){
    if(!window._probeHistory.length)return;
    let rows='';
    window._probeHistory.forEach((p,i)=>{
      const ok=p.ok;
      rows+='<tr><td class="'+(ok?'v-green':'v-red')+'">'+(ok?'✓':'✗')+'</td><td class="mono">'+h(p.host||'')+'</td><td class="mono">'+h(p.port||'')+'</td>'+
        '<td class="mono">'+(ok?p.rtt_ms+'ms':'—')+'</td><td class="mono">'+(p.status||'—')+'</td><td style="color:var(--z-muted)">'+h(p.time||'')+'</td></tr>';
    });
    $('pr-history').innerHTML='<div class="card mt-5"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Probe History</div></div><table><thead><tr><th></th><th>Host</th><th>Port</th><th>RTT</th><th>Status</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
  }
  renderHistory();
  window.doProbe=async function(){
    const host=$('pr-host').value.trim(),port=parseInt($('pr-port').value)||5060;
    if(!host)return;
    $('pr-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-muted)">Probing '+h(host)+':'+port+'...</div>';
    try{
      const r=await fetch('/api/probe',{method:'POST',headers:{...headers(),'Content-Type':'application/json'},body:JSON.stringify({host,port,wait_ms:3000})});
      const d=await r.json();
      const ok=d.ok===true;
      $('pr-r').innerHTML='<div class="card p-5"><div class="grid grid-cols-2 xl:grid-cols-4 gap-3">'+
        kpi('Result',ok?'Reachable':'Unreachable',h(d.error||''),ok?'v-green':'v-red')+
        kpi('RTT',ok?d.rtt_ms+'ms':'—','round trip time',ok?'v-blue':'v-red')+
        kpi('Status',d.status||'—','SIP response code','v-purple')+
        kpi('Target',host+':'+port,'',ok?'v-green':'v-red')+
        '</div></div>';
      window._probeHistory.unshift({ok,host,port,rtt_ms:d.rtt_ms,status:d.status,error:d.error,time:new Date().toLocaleTimeString()});
      if(window._probeHistory.length>20)window._probeHistory.pop();
      renderHistory();
    }catch(e){$('pr-r').innerHTML=errorCard('Probe failed: '+e.message);}
  };
};

// ===== ADMIN =====
pages['/admin']=function(){
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">Settings</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">System configuration and user management.</p>'+
    '<div class="grid xl:grid-cols-2 gap-5">'+
    '<div>'+
    '<div class="card p-5 mb-5"><div class="section-title mb-2">API Key</div><div class="flex gap-2"><input id="ak" type="password" value="'+h(KEY)+'" class="flex-1"><button onclick="localStorage.setItem(\'zaman_api_key\',document.getElementById(\'ak\').value);location.reload()" class="rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Save</button></div><p class="text-[10px] text-[var(--z-muted)] mt-2">Stored in localStorage. Sent as X-API-Key header with every request.</p></div>'+
    '<div class="card p-5"><div class="section-title mb-2">System Health</div><div id="ah">Loading...</div></div>'+
    '</div>'+
    '<div>'+
    '<div class="card p-5 mb-5"><div class="section-title mb-3">User Management</div><div id="user-list">Loading...</div>'+
    '<div class="mt-4 pt-4" style="border-top:1px solid var(--z-line)"><div class="section-title mb-2">Add User</div>'+
    '<div class="flex gap-2 flex-wrap"><input id="nu-name" placeholder="Username" class="w-32"><input id="nu-pw" type="password" placeholder="Password" class="w-32">'+
    '<select id="nu-role" class="w-28"><option value="viewer">Viewer</option><option value="operator">Operator</option><option value="admin">Admin</option></select>'+
    '<button onclick="addUser()" class="rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Add</button></div>'+
    '<div id="nu-err" class="text-xs text-[#ef4444] mt-1"></div></div></div>'+
    '</div></div>';

  async function loadUserList(){
    const users=await fetch('/web/users',{headers:headers()}).then(r=>r.ok?r.json():null);
    if(!users){$('user-list').innerHTML='<div class="text-xs" style="color:var(--z-muted)">Admin access required to manage users.</div>';return;}
    const roleBadge=r=>r==='admin'?'<span class="px-2 py-0.5 rounded-full text-[10px] font-semibold" style="background:rgba(248,113,113,.1);color:#f87171;border:1px solid rgba(248,113,113,.2)">admin</span>':r==='operator'?'<span class="px-2 py-0.5 rounded-full text-[10px] font-semibold" style="background:rgba(167,139,250,.1);color:#a78bfa;border:1px solid rgba(167,139,250,.2)">operator</span>':'<span class="px-2 py-0.5 rounded-full text-[10px] font-semibold" style="background:rgba(161,161,170,.1);color:#a1a1aa;border:1px solid rgba(161,161,170,.2)">viewer</span>';
    let rows='';
    users.forEach(u=>{
      rows+='<div class="flex items-center justify-between py-2.5" style="border-bottom:1px solid var(--z-line)">'+
        '<div class="flex items-center gap-2"><span class="text-sm font-medium">'+h(u.username)+'</span>'+roleBadge(u.role)+'</div>'+
        '<div class="flex gap-1">'+
        '<button onclick="resetPw('+u.id+',\''+h(u.username)+'\')" class="text-[10px] px-2 py-1 rounded" style="color:var(--z-muted);border:1px solid var(--z-line)">Reset pw</button>'+
        '<button onclick="deleteUser('+u.id+',\''+h(u.username)+'\')" class="text-[10px] px-2 py-1 rounded" style="color:#f87171;border:1px solid rgba(248,113,113,.2)">Delete</button>'+
        '</div></div>';
    });
    $('user-list').innerHTML=rows||'<div class="text-xs" style="color:var(--z-muted)">No users.</div>';
  }
  loadUserList();
  api('/api/health').then(d=>{if(d)$('ah').innerHTML='<pre class="text-xs mono p-3 rounded overflow-auto whitespace-pre-wrap" style="background:var(--z-field);border:1px solid var(--z-line)">'+h(JSON.stringify(d,null,2))+'</pre>';});

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
  $('main').innerHTML='<h1 class="text-lg font-semibold tracking-tight">Number Lookup</h1><p class="text-xs mt-0.5 mb-5" style="color:var(--z-muted)">Search call history by phone number or DID</p>'+
    '<div class="flex gap-2 mb-5"><input id="num-q" placeholder="Enter phone number (e.g. 7273491561)" value="'+h(preNum)+'" class="flex-1">'+
    '<button onclick="numSearch()" class="rounded-md px-3 py-1.5 text-xs font-medium cursor-pointer transition-colors" style="background:var(--z-ink);color:var(--z-bg)">Search</button></div>'+
    '<div id="num-r"></div>';
  $('num-q').addEventListener('keydown',e=>{if(e.key==='Enter')numSearch();});
  window.numSearch=async function(){
    const q=$('num-q').value.trim();if(!q)return;
    $('num-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-muted)">Searching...</div>';
    const d=await api('/api/number?q='+encodeURIComponent(q));
    if(!d||!d.total){$('num-r').innerHTML='<div class="card p-4 text-xs" style="color:var(--z-muted)">No calls found for '+h(q)+'.</div>';return;}
    const asrColor=d.asr>=70?'v-green':d.asr>=40?'v-yellow':'v-red';
    let cards='<div class="grid grid-cols-2 xl:grid-cols-5 gap-3 mb-5">'+
      kpi('Total Calls',d.total,'in last 60 min','v-blue')+
      kpi('Answered',d.answered,'completed','v-green')+
      kpi('Failed',d.failed,'rejected',d.failed>0?'v-red':'v-green')+
      kpi('ASR',d.asr+'%','answer rate',asrColor)+
      kpi('ACD',d.acd+'s','avg duration','v-purple')+'</div>';
    let rows='';
    (d.calls||[]).forEach(c=>{
      const sc=c.state==='completed'?'v-green':c.state==='failed'?'v-red':c.state==='in_progress'?'v-yellow':'';
      rows+='<tr class="cursor-pointer" onclick="location.hash=\'#/ladder?call_id='+encodeURIComponent(c.call_id||'')+'\'">'+
        '<td class="mono c-accent truncate max-w-[180px]">'+h(c.call_id||'')+'</td>'+
        '<td>'+agentHtml(c.agent)+'</td><td class="mono">'+h(c.src||'')+'</td><td class="mono">'+h(c.dst||'')+'</td>'+
        '<td class="'+sc+'">'+h(c.state)+'</td><td class="mono">'+(c.status||'')+'</td>'+
        '<td style="color:var(--z-muted)">'+(c.first_ts_ms?timeAgo(c.first_ts_ms):'')+'</td></tr>';
    });
    $('num-r').innerHTML=cards+'<div class="card"><div class="p-4" style="border-bottom:1px solid var(--z-line)"><div class="text-xs font-medium">Calls for '+h(q)+'</div></div><table><thead><tr><th>Call-ID</th><th>Server</th><th>Source</th><th>Destination</th><th>State</th><th>Code</th><th>Time</th></tr></thead><tbody>'+rows+'</tbody></table></div>';
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
    $('wb').innerHTML='<div class="grid grid-cols-4 gap-6 mb-8">'+
      '<div class="card p-8 text-center"><div class="text-[11px] uppercase tracking-widest" style="color:var(--z-dim)">Concurrent Calls</div><div class="text-5xl font-bold mono mt-3 v-pink">'+n(rt,'active_calls').toLocaleString()+'</div></div>'+
      '<div class="card p-8 text-center"><div class="text-[11px] uppercase tracking-widest" style="color:var(--z-dim)">CPS</div><div class="text-5xl font-bold mono mt-3 v-green">'+perSec(n(rt,'invites'),60)+'</div></div>'+
      '<div class="card p-8 text-center"><div class="text-[11px] uppercase tracking-widest" style="color:var(--z-dim)">ASR</div><div class="text-5xl font-bold mono mt-3 '+(asr>=70?'v-green':asr>=40?'v-yellow':'v-red')+'">'+asr+'%</div></div>'+
      '<div class="card p-8 text-center"><div class="text-[11px] uppercase tracking-widest" style="color:var(--z-dim)">Failures</div><div class="text-5xl font-bold mono mt-3 '+(fails>0?'v-red':'v-green')+'">'+fails+'</div></div>'+
      '</div>'+
      '<div class="grid grid-cols-6 gap-4">'+
      '<div class="card p-5 text-center"><div class="text-[10px]" style="color:var(--z-dim)">Msg/sec</div><div class="text-2xl font-bold mono mt-1">'+perSec(n(rt,'total'),60)+'</div></div>'+
      '<div class="card p-5 text-center"><div class="text-[10px]" style="color:var(--z-dim)">ACD</div><div class="text-2xl font-bold mono mt-1">'+n(rt,'acd_seconds')+'s</div></div>'+
      '<div class="card p-5 text-center"><div class="text-[10px]" style="color:var(--z-dim)">2xx</div><div class="text-2xl font-bold mono mt-1 v-green">'+n(rt,'resp_2xx').toLocaleString()+'</div></div>'+
      '<div class="card p-5 text-center"><div class="text-[10px]" style="color:var(--z-dim)">4xx</div><div class="text-2xl font-bold mono mt-1 v-yellow">'+n(rt,'resp_4xx').toLocaleString()+'</div></div>'+
      '<div class="card p-5 text-center"><div class="text-[10px]" style="color:var(--z-dim)">5xx</div><div class="text-2xl font-bold mono mt-1 v-red">'+n(rt,'resp_5xx').toLocaleString()+'</div></div>'+
      '<div class="card p-5 text-center"><div class="text-[10px]" style="color:var(--z-dim)">Agents</div><div class="text-2xl font-bold mono mt-1">'+n(rt,'agents_active')+'</div></div>'+
      '</div>'+
      '<div class="text-center mt-6 text-[10px]" style="color:var(--z-dim)">Zaman · '+new Date().toLocaleTimeString()+'</div>';
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
