// نسخ احتياطي: ملف عادي (.db) أو مشفّر AES-256-GCM (.db.enc) عند ضبط BACKUP_KEY.
// الاستخدام: node backup.js | node backup.js restore <ملف>
const fs=require('fs'),path=require('path'),crypto=require('crypto'),{execFile}=require('child_process');
const DIR=()=>path.resolve(process.env.BACKUP_DIR||'backups'),KEEP=()=>+process.env.KEEP_BACKUPS||14,hasKey=()=>!!process.env.BACKUP_KEY;
const key=()=>crypto.scryptSync(process.env.BACKUP_KEY,'acc-backup-v1',32);
const enc=b=>{const iv=crypto.randomBytes(12),c=crypto.createCipheriv('aes-256-gcm',key(),iv),d=Buffer.concat([c.update(b),c.final()]);return Buffer.concat([Buffer.from('ACC1'),iv,c.getAuthTag(),d])};
const dec=b=>{if(!hasKey())throw new Error('BACKUP_KEY مطلوب لفتح النسخة المشفرة');if(b.subarray(0,4).toString()!=='ACC1')throw new Error('ملف غير صالح');const d=crypto.createDecipheriv('aes-256-gcm',key(),b.subarray(4,16));d.setAuthTag(b.subarray(16,32));return Buffer.concat([d.update(b.subarray(32)),d.final()])};
const list=()=>{try{return fs.readdirSync(DIR()).filter(f=>f.startsWith('backup-')).sort().reverse()}catch(e){return[]}};
async function run(db){const D=DIR();fs.mkdirSync(D,{recursive:true});const tmp=path.join(D,'.tmp.db');try{fs.unlinkSync(tmp)}catch(e){}
 db.exec("VACUUM INTO '"+tmp.replace(/'/g,"''")+"'");const ts=new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);let out;
 if(hasKey()){out=path.join(D,'backup-'+ts+'.db.enc');fs.writeFileSync(out,enc(fs.readFileSync(tmp)));fs.unlinkSync(tmp)}
 else{out=path.join(D,'backup-'+ts+'.db');try{fs.unlinkSync(out)}catch(e){}fs.renameSync(tmp,out)}
 list().slice(KEEP()).forEach(f=>{try{fs.unlinkSync(path.join(D,f))}catch(e){}});
 if(process.env.BACKUP_HOOK)execFile('sh',['-c',process.env.BACKUP_HOOK,'sh',out],(e,so,se)=>e&&console.error('hook failed:',e.message,se));return out}
module.exports={run,enc,dec,list,dir:DIR};
if(require.main===module){const[,,cmd,file]=process.argv,dbf=process.env.DB_FILE||(process.env.LOCAL==='1'?'data/accounting.db':'data.db');
 if(cmd==='restore'){if(!file)throw new Error('حدد ملف النسخة');const raw=fs.readFileSync(file),buf=file.endsWith('.enc')?dec(raw):raw;[dbf+'-wal',dbf+'-shm'].forEach(f=>fs.existsSync(f)&&fs.unlinkSync(f));fs.writeFileSync(dbf,buf);console.log('تمت الاستعادة إلى',dbf,'— أعد تشغيل البرنامج')}
 else{const{DatabaseSync}=require('node:sqlite');run(new DatabaseSync(dbf)).then(f=>console.log('تم:',f))}}
