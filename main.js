// MauriStore — غلاف سطح المكتب (Electron): يشغّل الخادم المحلي داخل التطبيق ويعرض الواجهة في نافذة. لا يحتاج إنترنت.
const{app,BrowserWindow,Menu,shell,dialog,session}=require('electron'),path=require('path'),fs=require('fs'),net=require('net'),http=require('http');
const TITLE='MauriStore - برنامج محاسبة وإدارة المحل',MAIL='elhajmed410@gmail.com',sleep=ms=>new Promise(r=>setTimeout(r,ms));
if(!app.requestSingleInstanceLock()){app.quit()}else{
let win=null,srv=null,PORT=3737,cfg={lan:false,port:3737},quitting=false;
const DD=()=>process.env.MAURI_DATA||app.getPath('userData'),cfgFile=()=>path.join(DD(),'config.json');
const loadCfg=()=>{try{cfg={...cfg,...JSON.parse(fs.readFileSync(cfgFile(),'utf8'))}}catch(e){}};
const saveCfg=()=>{try{fs.mkdirSync(DD(),{recursive:true});fs.writeFileSync(cfgFile(),JSON.stringify(cfg))}catch(e){}};
const freePort=p=>new Promise(r=>{const s=net.createServer();s.once('error',()=>r(freePort(p+1)));s.listen(p,cfg.lan?'0.0.0.0':'127.0.0.1',()=>s.close(()=>r(p)))});
const ping=p=>new Promise(r=>{const q=http.get({host:'127.0.0.1',port:p,path:'/api/status',timeout:800},res=>{res.resume();r(res.statusCode===200)});q.on('error',()=>r(false));q.on('timeout',()=>{q.destroy();r(false)})});
const waitReady=async p=>{for(let i=0;i<80;i++){if(await ping(p))return true;await sleep(250)}return false};
const LOADING='<meta charset="utf-8"><body style="margin:0;height:100vh;display:grid;place-items:center;background:linear-gradient(150deg,#0c2250,#1b57c9);color:#fff;font:600 22px Segoe UI,Tahoma,sans-serif;text-align:center"><div><div style="font-size:54px;font-weight:800;direction:ltr">Mauri<span style="color:#2f7cff">Store</span></div><div style="margin-top:14px;opacity:.85">جارٍ التشغيل…</div></div>';

async function startServer(){
  PORT=await freePort(cfg.port||3000);
  Object.assign(process.env,{
    LOCAL:'1',
    PORT:String(PORT),
    HOST:cfg.lan?'0.0.0.0':'127.0.0.1',
    DB_FILE:path.join(DD(),'data','accounting.db'),
    BACKUP_DIR:process.env.MAURI_BACKUPS||path.join(app.getPath('documents'),'MauriStore','Backups'),
    THROTTLE_MAX:'60'
  });
  
  // تفعيل node:sqlite في بيئة Electron
  process.env.NODE_OPTIONS = (process.env.NODE_OPTIONS || '') + ' --experimental-sqlite';
  
  srv=require('./server/server.js');
  return waitReady(PORT);
}
const origin=()=>'http://127.0.0.1:'+PORT;
async function backupNow(){dialog.showMessageBox(win,{type:'info',title:'MauriStore',message:'يتم أخذ النسخ الاحتياطية تلقائياً في الخلفية'})}
function toggleLan(){cfg.lan=!cfg.lan;saveCfg();const r=dialog.showMessageBoxSync(win,{type:'question',buttons:['إعادة التشغيل الآن','لاحقًا'],defaultId:0,message:cfg.lan?'سيُسمح للأجهزة على نفس الشبكة بالاتصال (تأكد من جدار الحماية)':'سيقتصر الاتصال على هذا الحاسوب',detail:'يلزم إعادة تشغيل البرنامج لتطبيق التغيير.'});if(r===0){app.relaunch();app.exit(0)}}
function buildMenu(){Menu.setApplicationMenu(Menu.buildFromTemplate([
 {label:'ملف',submenu:[{label:'نسخة احتياطية الآن',click:backupNow},{label:'فتح مجلد النسخ الاحتياطية',click:()=>shell.openPath(process.env.BACKUP_DIR)},{label:'فتح مجلد البيانات',click:()=>shell.openPath(path.dirname(process.env.DB_FILE))},{type:'separator'},{label:'السماح بالاتصال من أجهزة الشبكة المحلية (جوال / كاشير ثانٍ)',type:'checkbox',checked:cfg.lan,click:toggleLan},{type:'separator'},{label:'خروج',role:'quit'}]},
 {label:'عرض',submenu:[{label:'إعادة تحميل',role:'reload'},{label:'ملء الشاشة',role:'togglefullscreen'},{label:'تكبير',role:'zoomIn'},{label:'تصغير',role:'zoomOut'},{label:'الحجم الافتراضي',role:'resetZoom'}]},
 {label:'مساعدة',submenu:[{label:'الدعم الفني',click:()=>shell.openExternal('mailto:'+MAIL)},{label:'حول البرنامج',click:()=>dialog.showMessageBox(win,{type:'info',title:'MauriStore',message:'MauriStore v1.0',detail:'برنامج محاسبة وإدارة المحل\nMauriTech\nفريق الدعم: '+MAIL+'\nالهاتف: 49131313'})}]}]))}
async function createWindow(){
win=new BrowserWindow({width:1440,height:880,minWidth:1000,minHeight:640,title:TITLE,icon:path.join(__dirname,'build','icon.ico'),backgroundColor:'#102a5b',show:false,autoHideMenuBar:true,webPreferences:{contextIsolation:true,nodeIntegration:false,sandbox:true,spellcheck:false}});
 win.once('ready-to-show',()=>win.show());win.on('page-title-updated',e=>e.preventDefault());win.on('closed',()=>{win=null});
 win.webContents.setWindowOpenHandler(({url})=>{if(/^(https?:|mailto:)/.test(url)&&!url.startsWith(origin()))shell.openExternal(url);return{action:'deny'}});
 win.webContents.on('will-navigate',(e,url)=>{if(!url.startsWith(origin())&&!url.startsWith('data:')){e.preventDefault();if(/^(https?:|mailto:)/.test(url))shell.openExternal(url)}});
 await win.loadURL('data:text/html;charset=utf-8,'+encodeURIComponent(LOADING));
 const up=await startServer().catch(()=>false);
 if(!up){dialog.showErrorBox('MauriStore','تعذّر تشغيل الخادم المحلي. أغلق أي نسخة أخرى من البرنامج وأعد المحاولة.');return app.exit(1)}
 await win.loadURL(origin()+'/');
 if(process.env.MAURI_SELFTEST){await sleep(1500);if(process.env.MAURI_SELFTEST_JS){try{const r=await win.webContents.executeJavaScript(process.env.MAURI_SELFTEST_JS);if(r!==undefined)console.log('SELFTEST_RESULT '+JSON.stringify(r))}catch(e){console.log('SELFTEST_ERROR '+e.message)}}await sleep(2500);fs.writeFileSync(process.env.MAURI_SELFTEST,(await win.webContents.capturePage()).toPNG());app.exit(0)}}
app.on('second-instance',()=>{if(win){if(win.isMinimized())win.restore();win.focus()}});
app.on('before-quit',async e=>{if(quitting)return;e.preventDefault();quitting=true;app.exit(0)});
app.on('window-all-closed',()=>app.quit());
app.whenReady().then(()=>{loadCfg();buildMenu();
 session.defaultSession.setPermissionRequestHandler((wc,perm,cb)=>cb(perm==='media'&&wc.getURL().startsWith(origin())));
 createWindow()})}