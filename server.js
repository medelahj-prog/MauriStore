// خادم المحاسبة: عدة متاجر (Tenants) + فروع + مستخدمون بصلاحيات + SQLite
const express=require('express'),{DatabaseSync}=require('node:sqlite'),bcrypt=require('bcryptjs'),jwt=require('jsonwebtoken'),path=require('path'),crypto=require('crypto'),os=require('os'),fs=require('fs');
let SECRET=process.env.JWT_SECRET;
const LOCAL=process.env.LOCAL==='1',DBF=process.env.DB_FILE||(LOCAL?'data/accounting.db':'data.db');fs.mkdirSync(path.dirname(path.resolve(DBF)),{recursive:true});
const raw=new DatabaseSync(DBF);raw.exec('PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;');
const nn=x=>x===undefined?null:x,wrap=st=>({run:(...a)=>st.run(...a.map(nn)),get:(...a)=>st.get(...a.map(nn)),all:(...a)=>st.all(...a.map(nn))});
const db={exec:x=>raw.exec(x),prepare:x=>wrap(raw.prepare(x)),transaction:fn=>(...a)=>{raw.exec('BEGIN IMMEDIATE');try{const r=fn(...a);raw.exec('COMMIT');return r}catch(e){try{raw.exec('ROLLBACK')}catch(_){}throw e}}};
db.exec(`
CREATE TABLE IF NOT EXISTS shops(id INTEGER PRIMARY KEY,name TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS branches(id INTEGER PRIMARY KEY,shop_id INT,name TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,shop_id INT,username TEXT UNIQUE,hash TEXT,role TEXT,branch_id INT);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,shop_id INT,code TEXT,name TEXT,cost REAL DEFAULT 0,price REAL DEFAULT 0,min REAL DEFAULT 5);
CREATE TABLE IF NOT EXISTS stock(product_id INT,branch_id INT,qty REAL DEFAULT 0,PRIMARY KEY(product_id,branch_id));
CREATE TABLE IF NOT EXISTS parties(id INTEGER PRIMARY KEY,shop_id INT,type TEXT,name TEXT,phone TEXT);
CREATE TABLE IF NOT EXISTS invoices(id INTEGER PRIMARY KEY,shop_id INT,branch_id INT,type TEXT,no TEXT,date TEXT,party_id INT,disc REAL,tax REAL,total REAL,paid REAL,user_id INT);
CREATE TABLE IF NOT EXISTS invoice_items(id INTEGER PRIMARY KEY,invoice_id INT,product_id INT,qty REAL,price REAL,cost REAL);
CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,shop_id INT,branch_id INT,party_id INT,type TEXT,amt REAL,date TEXT,note TEXT);
CREATE TABLE IF NOT EXISTS expenses(id INTEGER PRIMARY KEY,shop_id INT,branch_id INT,cat TEXT,amt REAL,note TEXT,date TEXT);
`);
for(const c of ["expires TEXT","status TEXT DEFAULT 'active'","plan TEXT DEFAULT 'trial'","legal_name TEXT","tax_id TEXT","address TEXT","phone TEXT","footer TEXT"])try{db.exec('ALTER TABLE shops ADD COLUMN '+c)}catch(e){}
db.exec(`CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,shop_id INT,user_id INT,action TEXT,detail TEXT,at TEXT DEFAULT CURRENT_TIMESTAMP);CREATE TABLE IF NOT EXISTS resets(user_id INT,hash TEXT,expires INT);`);
for(const[t,c]of [['shops','logo TEXT'],['parties','credit_limit REAL DEFAULT 0'],['invoices','due TEXT'],['invoices','client_id TEXT'],['invoices','pay_method TEXT'],['invoices','pay_note TEXT'],['payments','method TEXT'],['parties','note TEXT'],['invoices','at TEXT'],['payments','at TEXT'],['expenses','at TEXT']])try{db.exec(`ALTER TABLE ${t} ADD COLUMN ${c}`)}catch(e){}
try{db.exec('CREATE UNIQUE INDEX IF NOT EXISTS ux_inv_client ON invoices(shop_id,client_id) WHERE client_id IS NOT NULL')}catch(e){}
db.exec(`CREATE TABLE IF NOT EXISTS stock_moves(id INTEGER PRIMARY KEY,shop_id INT,branch_id INT,product_id INT,kind TEXT,delta REAL,after REAL,note TEXT,user_id INT,at TEXT DEFAULT CURRENT_TIMESTAMP);CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY,v TEXT);`);
try{db.exec('ALTER TABLE users ADD COLUMN tv INTEGER DEFAULT 0')}catch(e){}
if(!SECRET){const m=db.prepare("SELECT v FROM meta WHERE k='jwt'").get();SECRET=m?m.v:crypto.randomBytes(32).toString('hex');if(!m)db.prepare("INSERT INTO meta VALUES('jwt',?)").run(SECRET)}
db.exec(`CREATE TABLE IF NOT EXISTS pay_methods(id INTEGER PRIMARY KEY,shop_id INT,name TEXT,kind TEXT);CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY,shop_id INT,branch_id INT,party_id INT,amt REAL,note TEXT,date TEXT,user_id INT);`);
const ensureMethods=s=>{if(!db.prepare('SELECT 1 FROM pay_methods WHERE shop_id=?').get(s))for(const[n,k]of [['نقدًا','cash'],['بنكيلي','bank'],['مصرفي','bank'],['تحويل بنكي','bank'],['آجل (دين)','credit']])db.prepare('INSERT INTO pay_methods(shop_id,name,kind) VALUES(?,?,?)').run(s,n,k)};
const nowTs=()=>new Date().toISOString().slice(0,19).replace('T',' ');
const r2=x=>Math.round((x+Number.EPSILON)*100)/100;
const bk=require('./backup');
const app=express();if(process.env.TRUST_PROXY)app.set('trust proxy',1);
app.use((q,s,n)=>{s.set({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Strict-Transport-Security':'max-age=31536000'});n()});
app.use(express.json({limit:'1mb'}));app.use(express.static(__dirname));
const err=(m,c=400)=>Object.assign(new Error(m),{code:c});
const h=f=>(q,s)=>{try{s.json(f(q,s)??{ok:1})}catch(e){s.status(e.code||(/UNIQUE/.test(e.message)?409:500)).json({error:e.message})}};
const sign=u=>jwt.sign({id:u.id,shop:u.shop_id,role:u.role,branch:u.branch_id,tv:u.tv||0},SECRET,{expiresIn:'12h'});
const today=()=>new Date().toISOString().slice(0,10),P=(sql)=>db.prepare(sql);
// حماية بسيطة من تخمين كلمات المرور (10 محاولات / 15 دقيقة لكل IP) — استخدم nginx/Cloudflare للحماية الأقوى
const tries={};const throttle=(ip)=>{const n=Date.now(),t=(tries[ip]||[]).filter(x=>n-x<9e5);if(t.length>=(+process.env.THROTTLE_MAX||10))throw err('محاولات كثيرة، حاول لاحقًا',429);t.push(n);tries[ip]=t};
const addDays=(d,n)=>new Date(Date.parse(d)+n*864e5).toISOString().slice(0,10);
const audit=(s,u,a,d='')=>{P('INSERT INTO audit(shop_id,user_id,action,detail) VALUES(?,?,?,?)').run(s,u,a,String(d))};
const sha=x=>crypto.createHash('sha256').update(String(x)).digest('hex');
const mkShop=(name,username,password,days,plan)=>{if(!name||!username||(password||'').length<8)throw err('بيانات ناقصة (كلمة المرور 8 أحرف فأكثر)');
 return db.transaction(()=>{const s=P('INSERT INTO shops(name,plan,expires) VALUES(?,?,?)').run(name,plan,addDays(today(),days)).lastInsertRowid,b=P('INSERT INTO branches(shop_id,name) VALUES(?,?)').run(s,'الفرع الرئيسي').lastInsertRowid,
 u=P('INSERT INTO users(shop_id,username,hash,role,branch_id) VALUES(?,?,?,?,?)').run(s,username,bcrypt.hashSync(password,10),'admin',b).lastInsertRowid;audit(s,u,'shop_created',plan);return{shop:s,user:u,branch:b}})()};
const fails={};const lockedOut=k=>(fails[k]=(fails[k]||[]).filter(x=>Date.now()-x<9e5)).length>=5;
app.get('/api/status',h(()=>{const setup=!P('SELECT 1 FROM shops').get();return{local:LOCAL,setup,signup:LOCAL?setup:process.env.ALLOW_SIGNUP!=='0'}}));
app.post('/api/signup',h(q=>{if(process.env.ALLOW_SIGNUP==='0')throw err('التسجيل مغلق',403);if(LOCAL&&P('SELECT 1 FROM shops').get())throw err('تم إعداد البرنامج مسبقًا',403);throttle(q.ip);
 const r=mkShop(q.body.shop,q.body.username,q.body.password,+(process.env.LICENSE_DAYS??process.env.TRIAL_DAYS??180),'standard');return{token:sign({id:r.user,shop_id:r.shop,role:'admin',branch_id:r.branch})}}));
app.post('/api/login',h(q=>{throttle(q.ip);const k=String(q.body.username||'').toLowerCase();if(lockedOut(k))throw err('الحساب مقفل مؤقتًا بعد محاولات فاشلة، حاول بعد 15 دقيقة',429);
 const u=P('SELECT * FROM users WHERE username=?').get(q.body.username||'');
 if(!u||!bcrypt.compareSync(q.body.password||'',u.hash)){fails[k].push(Date.now());throw err('بيانات الدخول خاطئة',401)}
 delete fails[k];return{token:sign(u),role:u.role,branch:u.branch_id}}));
// استرجاع كلمة المرور برمز يصدره المزوّد (بدون بريد إلكتروني)
app.post('/api/reset',h(q=>{throttle(q.ip);const{username,code,password}=q.body;if((password||'').length<8)throw err('كلمة المرور 8 أحرف فأكثر');
 const u=P('SELECT * FROM users WHERE username=?').get(username||''),r=u&&P('SELECT * FROM resets WHERE user_id=?').get(u.id);
 if(!r||r.expires<Date.now()||r.hash!==sha(String(code||'').toUpperCase()))throw err('رمز غير صالح أو منتهٍ');
 P('UPDATE users SET hash=?,tv=tv+1 WHERE id=?').run(bcrypt.hashSync(password,10),u.id);P('DELETE FROM resets WHERE user_id=?').run(u.id);delete fails[String(username).toLowerCase()];audit(u.shop_id,u.id,'password_reset')}));
// لوحة المزوّد (أنت): محمية بـ ADMIN_KEY
const vend=(q,s,n)=>{const k=process.env.ADMIN_KEY;if(!k)return s.status(503).json({error:'ADMIN_KEY غير معرّف'});
 const a=Buffer.from(String(q.headers['x-admin-key']||'')),b=Buffer.from(k);
 if(a.length!==b.length||!crypto.timingSafeEqual(a,b)){try{throttle(q.ip)}catch(e){return s.status(429).json({error:e.message})}return s.status(401).json({error:'مفتاح خاطئ'})}n()};
const V=express.Router();app.use('/vendor',vend,V);
V.get('/shops',h(()=>P('SELECT s.id,s.name,s.plan,s.status,s.expires,(SELECT COUNT(*) FROM users u WHERE u.shop_id=s.id) users FROM shops s ORDER BY s.id DESC').all()));
V.post('/shops',h(q=>{const{name,username,password,days=180,plan='standard'}=q.body;return mkShop(name,username,password,+days,plan)}));
V.post('/shops/:id/renew',h(q=>{const s=P('SELECT * FROM shops WHERE id=?').get(q.params.id);if(!s)throw err('غير موجود',404);const d=+q.body.days;if(!q.body.expires&&!(d>0))throw err('days أو expires مطلوب');
 const e=q.body.expires||addDays(s.expires&&s.expires>today()?s.expires:today(),d);P("UPDATE shops SET expires=?,status='active',plan=COALESCE(?,plan) WHERE id=?").run(e,q.body.plan||null,s.id);audit(s.id,0,'renewed',e);return{expires:e}}));
V.post('/shops/:id/suspend',h(q=>{P("UPDATE shops SET status='suspended' WHERE id=?").run(q.params.id);audit(q.params.id,0,'suspended')}));
V.post('/shops/:id/activate',h(q=>{P("UPDATE shops SET status='active' WHERE id=?").run(q.params.id);audit(q.params.id,0,'activated')}));
V.post('/shops/:id/reset-code',h(q=>{const u=q.body.username?P('SELECT * FROM users WHERE username=? AND shop_id=?').get(q.body.username,q.params.id):P("SELECT * FROM users WHERE shop_id=? AND role='admin' ORDER BY id LIMIT 1").get(q.params.id);
 if(!u)throw err('مستخدم غير موجود',404);const code=crypto.randomBytes(5).toString('hex').toUpperCase();P('DELETE FROM resets WHERE user_id=?').run(u.id);
 P('INSERT INTO resets VALUES(?,?,?)').run(u.id,sha(code),Date.now()+36e5);audit(u.shop_id,0,'reset_code_issued',u.username);return{username:u.username,code,valid_minutes:60}}));
V.post('/backup',(q,s)=>bk.run(db).then(f=>s.json({file:f})).catch(e=>s.status(500).json({error:e.message})));
const api=express.Router();
app.use('/api',(q,s,n)=>{try{q.u=jwt.verify((q.headers.authorization||'').slice(7),SECRET)}catch(e){return s.status(401).json({error:'غير مصرح'})}
 const sh=P('SELECT plan,status,expires FROM shops WHERE id=?').get(q.u.shop);if(!sh)return s.status(401).json({error:'غير مصرح'});const us=P('SELECT tv,role,branch_id FROM users WHERE id=? AND shop_id=?').get(q.u.id,q.u.shop);if(!us||(us.tv||0)!==(q.u.tv||0))return s.status(401).json({error:'انتهت الجلسة'});q.u.role=us.role;q.u.branch=us.branch_id;
 const late=sh.expires?Math.floor((Date.parse(today())-Date.parse(sh.expires))/864e5):0,ro=late>+(process.env.GRACE_DAYS??3);
 q.lic={plan:sh.plan,status:sh.status,expires:sh.expires,days_left:sh.expires?-late:null,readonly:ro};
 if(sh.status!=='active'&&q.path!=='/license')return s.status(402).json({error:'الاشتراك موقوف، تواصل مع المزوّد',code:'SUSPENDED'});
 if(ro&&q.method!=='GET'&&q.path!=='/password'&&q.path!=='/license/activate')return s.status(402).json({error:'انتهى الاشتراك: النظام للقراءة فقط، جدّد اشتراكك',code:'EXPIRED'});n()},api);
const only=(...r)=>(q,s,n)=>r.includes(q.u.role)?n():s.status(403).json({error:'ممنوع'});
const br=q=>{const b=q.u.role==='admin'?+(q.query.branch||q.body?.branch_id||q.u.branch):q.u.branch;
 if(!P('SELECT 1 FROM branches WHERE id=? AND shop_id=?').get(b,q.u.shop))throw err('فرع غير صالح');return b};
const ownParty=(id,shop)=>{if(id&&!P('SELECT 1 FROM parties WHERE id=? AND shop_id=?').get(id,shop))throw err('طرف غير صالح')};
// الفروع والمستخدمون
api.get('/branches',h(q=>P('SELECT * FROM branches WHERE shop_id=?').all(q.u.shop)));
api.post('/branches',only('admin'),h(q=>({id:P('INSERT INTO branches(shop_id,name) VALUES(?,?)').run(q.u.shop,q.body.name).lastInsertRowid})));
api.get('/users',only('admin'),h(q=>P('SELECT id,username,role,branch_id FROM users WHERE shop_id=?').all(q.u.shop)));
api.post('/users',only('admin'),h(q=>{const{username,password,role,branch_id}=q.body;if(!['admin','cashier'].includes(role)||(password||'').length<8)throw err('بيانات غير صالحة (كلمة المرور 8 أحرف فأكثر)');
 if(!P('SELECT 1 FROM branches WHERE id=? AND shop_id=?').get(branch_id,q.u.shop))throw err('فرع غير صالح');
 return{id:P('INSERT INTO users(shop_id,username,hash,role,branch_id) VALUES(?,?,?,?,?)').run(q.u.shop,username,bcrypt.hashSync(password,10),role,branch_id).lastInsertRowid}}));
// المنتجات (الكمية لكل فرع)
api.get('/products',h(q=>{
 const b=br(q), s=q.u.shop;
 return P(`SELECT p.*,COALESCE(st.qty,0) qty,
   (SELECT COALESCE(SUM(CASE WHEN delta>0 THEN delta ELSE 0 END),0) FROM stock_moves WHERE product_id=p.id AND branch_id=?) added
   FROM products p LEFT JOIN stock st ON st.product_id=p.id AND st.branch_id=? WHERE p.shop_id=?`).all(b,b,s);
}));
api.post('/products',only('admin'),h(q=>{const{code,name,cost,price,min,qty}=q.body;if(!name)throw err('الاسم مطلوب');const b=br(q);
 return db.transaction(()=>{const id=P('INSERT INTO products(shop_id,code,name,cost,price,min) VALUES(?,?,?,?,?,?)').run(q.u.shop,code,name,cost||0,price||0,min??5).lastInsertRowid;
 if(qty){
   // إضافة الكمية للمخزون
   P('INSERT INTO stock VALUES(?,?,?)').run(id,b,qty);
   // تسجيل الحركة في السجل (هذا هو السطر الناقص)
   P('INSERT INTO stock_moves(shop_id,branch_id,product_id,kind,delta,after,note,user_id) VALUES(?,?,?,?,?,?,?,?)').run(q.u.shop,b,id,'add',qty,qty,'رصيد افتتاحي',q.u.id);
 }
 return{id}})()}));
api.put('/products/:id',only('admin'),h(q=>{
 const{code,name,cost,price,min,qty}=q.body, b=br(q), pid=q.params.id;
 return db.transaction(()=>{
  P('UPDATE products SET code=?,name=?,cost=?,price=?,min=? WHERE id=? AND shop_id=?').run(code,name,cost,price,min,pid,q.u.shop);
  if(qty!==undefined && qty!=='') {
    const n=+qty;
    const cur=(P('SELECT qty FROM stock WHERE product_id=? AND branch_id=?').get(pid,b)||{qty:0}).qty;
    if(n>0){
      P('INSERT INTO stock VALUES(?,?,?) ON CONFLICT(product_id,branch_id) DO UPDATE SET qty=qty+?').run(pid,b,n,n);
      P('INSERT INTO stock_moves(shop_id,branch_id,product_id,kind,delta,after,note,user_id) VALUES(?,?,?,?,?,?,?,?)').run(q.u.shop,b,pid,'add',n,cur+n,'إضافة كمية',q.u.id);
    }
  }
 })()
}));
api.put('/expenses/:id',only('admin'),h(q=>{if(!(+q.body.amt>0))throw err('المبلغ مطلوب');P('UPDATE expenses SET cat=?,amt=?,note=? WHERE id=? AND shop_id=?').run(q.body.cat||'أخرى',+q.body.amt,q.body.note||'',q.params.id,q.u.shop);audit(q.u.shop,q.u.id,'expense_updated',q.params.id)}));
api.delete('/expenses/:id',only('admin'),h(q=>{P('DELETE FROM expenses WHERE id=? AND shop_id=?').run(q.params.id,q.u.shop);audit(q.u.shop,q.u.id,'expense_deleted',q.params.id)}));
api.delete('/products/:id',only('admin'),h(q=>{P('DELETE FROM products WHERE id=? AND shop_id=?').run(q.params.id,q.u.shop)}));
// العملاء والموردون (type=customer|supplier) مع الرصيد
const BAL=`COALESCE((SELECT SUM(CASE WHEN type IN('sale','purchase') THEN total-paid ELSE -total END) FROM invoices WHERE party_id=p.id),0)-COALESCE((SELECT SUM(amt) FROM payments WHERE party_id=p.id),0)+COALESCE((SELECT SUM(amt) FROM ledger WHERE party_id=p.id),0)`;
api.get('/parties',h(q=>P(`SELECT p.*,${BAL} balance FROM parties p WHERE shop_id=? AND type=?`).all(q.u.shop,q.query.type||'customer')));
api.post('/parties',h(q=>{if(!q.body.name||!['customer','supplier'].includes(q.body.type))throw err('بيانات غير صالحة');return{id:P('INSERT INTO parties(shop_id,type,name,phone,credit_limit,note) VALUES(?,?,?,?,?,?)').run(q.u.shop,q.body.type,q.body.name,q.body.phone||'',+q.body.credit_limit||0,String(q.body.note||'').slice(0,300)).lastInsertRowid}}));
api.put('/parties/:id',h(q=>{const{name,phone,credit_limit,note}=q.body;if(!name)throw err('الاسم مطلوب');P('UPDATE parties SET name=?,phone=?,credit_limit=?,note=COALESCE(?,note) WHERE id=? AND shop_id=?').run(name,phone||'',+credit_limit||0,note==null?null:String(note).slice(0,300),q.params.id,q.u.shop)}));
api.get('/parties/:id/statement',h(q=>{const p=P('SELECT * FROM parties WHERE id=? AND shop_id=?').get(q.params.id,q.u.shop);if(!p)throw err('غير موجود',404);
 const e=[...P('SELECT id,date,no,type,total,paid,due,pay_method FROM invoices WHERE party_id=?').all(p.id).map(x=>({d:x.date,k:'i',id:x.id,type:x.type,no:x.no,due:x.due,pm:x.pay_method,a:['sale','purchase'].includes(x.type)?x.total-x.paid:-x.total})),
 ...P('SELECT id,date,amt,note,method FROM payments WHERE party_id=?').all(p.id).map(x=>({d:x.date,k:'p',id:x.id,note:x.note,pm:x.method,a:-x.amt})),...P('SELECT id,date,amt,note FROM ledger WHERE party_id=?').all(p.id).map(x=>({d:x.date,k:'l',id:x.id,note:x.note,a:x.amt}))].sort((a,b)=>a.d.localeCompare(b.d)||(a.k+a.id).localeCompare(b.k+b.id));
 let r=0;e.forEach(x=>{r+=x.a;x.bal=r});return{party:p,entries:e,balance:r}}));
api.delete('/parties/:id',only('admin'),h(q=>{P('DELETE FROM parties WHERE id=? AND shop_id=?').run(q.params.id,q.u.shop)}));
// الفواتير: كل شيء داخل Transaction والسيرفر هو من يحسب الإجمالي والمخزون
const SG={sale:-1,purchase:1,sale_return:1,purchase_return:-1};
api.post('/invoices',h(q=>{const{type,party_id,items,disc=0,tax_rate=0,paid,due,client_id,pay_method,pay_note}=q.body,sg=SG[type];if(due&&!/^\d{4}-\d{2}-\d{2}$/.test(due))throw err('تاريخ الاستحقاق غير صالح');if(!sg)throw err('نوع غير صالح');
 if(q.u.role!=='admin'&&type!=='sale')throw err('غير مصرح',403);if(!Array.isArray(items)||!items.length)throw err('لا توجد أصناف');
 const b=br(q);ownParty(party_id,q.u.shop);if(client_id){const e=P('SELECT id,no,total FROM invoices WHERE shop_id=? AND client_id=?').get(q.u.shop,String(client_id));if(e)return e}
 return db.transaction(()=>{let sub=0;const rows=items.map(i=>{const p=P('SELECT * FROM products WHERE id=? AND shop_id=?').get(i.product_id,q.u.shop),n=+i.qty,pr=+i.price;
  if(!p||!(n>0)||!(pr>=0))throw err('صنف أو كمية غير صالحة');const st=P('SELECT qty FROM stock WHERE product_id=? AND branch_id=?').get(p.id,b);
  if(sg<0&&(st?.qty||0)<n)throw err('الكمية غير متوفرة: '+p.name);sub+=n*pr;
  if(type==='purchase'){const tq=P('SELECT COALESCE(SUM(qty),0) q FROM stock WHERE product_id=?').get(p.id).q,nc=tq>0?Math.round((tq*p.cost+n*pr)/(tq+n)*10000)/10000:pr;P('UPDATE products SET cost=? WHERE id=?').run(nc,p.id)}
  P('INSERT INTO stock VALUES(?,?,?) ON CONFLICT(product_id,branch_id) DO UPDATE SET qty=qty+?').run(p.id,b,sg*n,sg*n);
  return[p.id,n,pr,type==='purchase'?pr:p.cost]});
 ensureMethods(q.u.shop);const pm=pay_method?P('SELECT * FROM pay_methods WHERE shop_id=? AND name=?').get(q.u.shop,pay_method):null;if(pay_method&&!pm)throw err('طريقة دفع غير معروفة');if(pm&&pm.kind==='credit'&&!party_id)throw err('الدين الآجل يتطلب اختيار العميل أو المورد');sub=r2(sub);if(!(disc>=0&&disc<=sub)||!(tax_rate>=0&&tax_rate<=100)||(paid!=null&&!(paid>=0)))throw err('قيم غير صالحة (خصم/ضريبة/مدفوع)');const tax=r2((sub-disc)*tax_rate/100),total=r2(sub-disc+tax),pd=party_id?r2(Math.min(paid??(pm&&pm.kind==='credit'?0:total),total)):total,
 no=type.split('_').map(x=>x[0].toUpperCase()).join('')+'-'+(1001+P('SELECT COUNT(*) c FROM invoices WHERE shop_id=?').get(q.u.shop).c);
 const id=P('INSERT INTO invoices(shop_id,branch_id,type,no,date,party_id,disc,tax,total,paid,user_id,due,client_id,pay_method,pay_note,at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)').run(q.u.shop,b,type,no,today(),party_id||null,disc,tax,total,pd,q.u.id,due||null,client_id?String(client_id):null,pay_method||null,String(pay_note||'').slice(0,200),nowTs()).lastInsertRowid;
 rows.forEach(r=>P('INSERT INTO invoice_items(invoice_id,product_id,qty,price,cost) VALUES(?,?,?,?,?)').run(id,...r));if(type==='sale'&&party_id){const L=P('SELECT credit_limit l FROM parties WHERE id=?').get(party_id).l;if(L>0&&P(`SELECT ${BAL} b FROM parties p WHERE id=?`).get(party_id).b>L+0.005)throw err('تجاوز الحد الائتماني للعميل')}audit(q.u.shop,q.u.id,'invoice',type+' '+no+' '+total);return{id,no,total}})()}));
// دالة حذف / إلغاء الفاتورة نهائياً
api.delete('/invoices/:id',only('admin'),h(q=>{
  const b=br(q), s=q.u.shop, id=q.params.id;
  return db.transaction(()=>{
    // جلب الفاتورة للتأكد من وجودها
    const inv=P('SELECT * FROM invoices WHERE id=? AND shop_id=?').get(id,s);
    if(!inv) throw err('الفاتورة غير موجودة');
    if(inv.type.includes('return')) throw err('لا يمكن إلغاء مرتجع، قم بعمل فاتورة بيع جديدة');
    
    // إرجاع الكميات إلى المخزون
    const items=P('SELECT * FROM invoice_items WHERE invoice_id=?').all(id);
    for(const it of items){
      // إذا كانت الفاتورة بيع، نرجع الكمية (+)، إذا كانت شراء نخصمها (-)
      const sg = inv.type==='sale' ? 1 : -1; 
      const cur = P('SELECT qty FROM stock WHERE product_id=? AND branch_id=?').get(it.product_id, b);
      const nq = (cur?.qty||0) + (it.qty * sg);
      
      P('INSERT INTO stock VALUES(?,?,?) ON CONFLICT(product_id,branch_id) DO UPDATE SET qty=?').run(it.product_id, b, nq, nq);
      
      // تسجيل الحركة في سجل المخزون
      P('INSERT INTO stock_moves(shop_id,branch_id,product_id,kind,delta,after,note,user_id) VALUES(?,?,?,?,?,?,?,?)').run(s,b,it.product_id,'void',it.qty*sg,nq,'إلغاء فاتورة '+inv.no,q.u.id);
    }
    
    // حذف الفاتورة وأصنافها
    P('DELETE FROM invoice_items WHERE invoice_id=?').run(id);
    P('DELETE FROM invoices WHERE id=?').run(id);
    
    // تسجيل العملية في سجل النظام
    audit(s, q.u.id, 'invoice_voided', inv.no);
    return { ok: 1 };
  })()
}));
api.get('/invoices',h(q=>{const k='%'+(q.query.q||'')+'%',t=q.query.type||'';return P(`SELECT i.*,(SELECT name FROM parties WHERE id=i.party_id) party FROM invoices i WHERE shop_id=? AND date BETWEEN ? AND ? AND (?=1 OR branch_id=?) AND (?='' OR type LIKE ?) AND (no LIKE ? OR COALESCE((SELECT name FROM parties WHERE id=i.party_id),'') LIKE ?) ORDER BY id DESC LIMIT ? OFFSET ?`).all(q.u.shop,q.query.from||'0000',q.query.to||'9999',q.u.role==='admin'?1:0,q.u.branch,t,t+'%',k,k,Math.min(+q.query.limit||30,200),+q.query.offset||0)}));
api.get('/invoices/:id/items',h(q=>P('SELECT i.* FROM invoice_items i JOIN invoices v ON v.id=i.invoice_id WHERE v.id=? AND v.shop_id=?').all(q.params.id,q.u.shop)));
// السداد/التحصيل والمصروفات
api.post('/payments',h(q=>{const{party_id,type,amt,note,method}=q.body;if(!(amt>0)||!['customer','supplier'].includes(type)||!party_id)throw err('بيانات غير صالحة');ownParty(party_id,q.u.shop);
 return{id:P('INSERT INTO payments(shop_id,branch_id,party_id,type,amt,date,note,method,at) VALUES(?,?,?,?,?,?,?,?,?)').run(q.u.shop,br(q),party_id,type,amt,today(),note||'',method||null,nowTs()).lastInsertRowid}}));
api.post('/expenses',only('admin'),h(q=>{if(!(q.body.amt>0))throw err('المبلغ مطلوب');return{id:P('INSERT INTO expenses(shop_id,branch_id,cat,amt,note,date,at) VALUES(?,?,?,?,?,?,?)').run(q.u.shop,br(q),q.body.cat||'أخرى',q.body.amt,q.body.note||'',today(),nowTs()).lastInsertRowid}}));
api.get('/expenses',only('admin'),h(q=>P('SELECT * FROM expenses WHERE shop_id=? ORDER BY id DESC LIMIT 500').all(q.u.shop)));
// التقرير
api.get('/reports/summary',only('admin'),h(q=>{const a=q.query.from||'0000',b=q.query.to||'9999',s=q.u.shop;
 const rv=t=>P('SELECT COALESCE(SUM(total-tax),0) x FROM invoices WHERE shop_id=? AND type=? AND date BETWEEN ? AND ?').get(s,t,a,b).x,
 cg=t=>P('SELECT COALESCE(SUM(i.qty*i.cost),0) x FROM invoice_items i JOIN invoices v ON v.id=i.invoice_id WHERE v.shop_id=? AND v.type=? AND v.date BETWEEN ? AND ?').get(s,t,a,b).x,
 ex=P('SELECT COALESCE(SUM(amt),0) x FROM expenses WHERE shop_id=? AND date BETWEEN ? AND ?').get(s,a,b).x,
 revenue=rv('sale')-rv('sale_return'),cogs=cg('sale')-cg('sale_return');return{revenue,cogs,gross:revenue-cogs,expenses:ex,net:revenue-cogs-ex}}));

// --- الكود الجديد المضاف لتقرير المخزون والمنتجات الأكثر مبيعاً ---
api.get('/reports/stock',only('admin'),h(q=>{
 const s=q.u.shop;
 // المنتجات الأكثر مبيعاً
 const top= P(`SELECT p.name,SUM(i.qty) qty,SUM(i.qty*i.price) revenue FROM invoice_items i JOIN invoices v ON v.id=i.invoice_id JOIN products p ON p.id=i.product_id WHERE v.shop_id=? AND v.type='sale' AND v.date BETWEEN ? AND ? GROUP BY p.id ORDER BY qty DESC LIMIT 10`).all(s,q.query.from||'0000',q.query.to||'9999');
 // حركات المخزون (الإضافات)
 const moves= P(`SELECT m.at,m.kind,m.delta,m.after,m.note,p.name product,(SELECT name FROM branches WHERE id=m.branch_id) branch FROM stock_moves m JOIN products p ON p.id=m.product_id WHERE m.shop_id=? ORDER BY m.id DESC LIMIT 50`).all(s);
 return {top, moves};
}));
const sum=(a,f)=>a.reduce((t,x)=>t+f(x),0);
api.get('/reports/aging',only('admin'),h(q=>{const tp=q.query.type==='supplier'?'supplier':'customer',iv=tp==='supplier'?'purchase':'sale',out=[];
 for(const p of P('SELECT * FROM parties WHERE shop_id=? AND type=?').all(q.u.shop,tp)){
  let cr=sum(P('SELECT amt FROM payments WHERE party_id=?').all(p.id),x=>x.amt)+sum(P('SELECT total FROM invoices WHERE party_id=? AND type=?').all(p.id,iv+'_return'),x=>x.total);const bk=[0,0,0,0,0];
  for(const x of [...P('SELECT date,due,total,paid FROM invoices WHERE party_id=? AND type=? ORDER BY date,id').all(p.id,iv),...P('SELECT date,NULL due,amt total,0 paid FROM ledger WHERE party_id=?').all(p.id)].sort((a,b)=>a.date.localeCompare(b.date))){let r=x.total-x.paid;const t=Math.min(r,cr);r-=t;cr-=t;if(r<=0.005)continue;
   const d=Math.floor((Date.parse(today())-Date.parse(x.due||x.date))/864e5);bk[d<=0?0:d<=30?1:d<=60?2:d<=90?3:4]+=r}
  const tot=sum(bk,x=>x);if(tot>0.005)out.push({id:p.id,name:p.name,phone:p.phone,balance:tot,current:bk[0],d30:bk[1],d60:bk[2],d90:bk[3],d90p:bk[4]})}
 return out.sort((a,b)=>b.balance-a.balance)}));
api.get('/reports/daily',h(q=>{const d=q.query.date||today(),b=br(q),s=q.u.shop,A=q.u.role==='admin',m=[];
 const iv=P('SELECT * FROM invoices WHERE shop_id=? AND date=? AND branch_id=?').all(s,d,b),pay=P('SELECT p.*,(SELECT name FROM parties WHERE id=p.party_id) party FROM payments p WHERE shop_id=? AND date=? AND branch_id=?').all(s,d,b),ex=A?P('SELECT * FROM expenses WHERE shop_id=? AND date=? AND branch_id=?').all(s,d,b):[];
 iv.forEach(x=>{if(x.type==='sale')m.push({k:'sale',r:x.no,m:x.pay_method,a:x.party_id?x.paid:x.total});else if(x.type==='purchase')m.push({k:'purchase',r:x.no,m:x.pay_method,a:-(x.party_id?x.paid:x.total)});else if(x.type==='sale_return'&&!x.party_id)m.push({k:'sale_return',r:x.no,m:x.pay_method,a:-x.total});else if(x.type==='purchase_return'&&!x.party_id)m.push({k:'purchase_return',r:x.no,m:x.pay_method,a:x.total})});
 pay.forEach(x=>m.push({k:x.type==='customer'?'collect':'pay',r:x.party||'',m:x.method,a:x.type==='customer'?x.amt:-x.amt}));ex.forEach(x=>m.push({k:'expense',r:x.cat,a:-x.amt}));
 ensureMethods(s);const kd={};P('SELECT name,kind FROM pay_methods WHERE shop_id=?').all(s).forEach(x=>kd[x.name]=x.kind);const mc=m.filter(x=>!x.m||(kd[x.m]||'cash')==='cash'),bm={};m.forEach(x=>{const n=x.m||'نقدًا',e=bm[n]||(bm[n]={name:n,in:0,out:0});if(x.a>0)e.in+=x.a;else e.out-=x.a});const S=iv.filter(x=>x.type==='sale'),R=iv.filter(x=>x.type==='sale_return');
 return{date:d,sales_count:S.length,sales:sum(S,x=>x.total),returns:sum(R,x=>x.total),discounts:sum(S,x=>x.disc),tax:sum(S,x=>x.tax)-sum(R,x=>x.tax),credit_sales:sum(S,x=>x.total-x.paid),cash_in:sum(mc.filter(x=>x.a>0),x=>x.a),cash_out:-sum(mc.filter(x=>x.a<0),x=>x.a),net_cash:sum(mc,x=>x.a),by_method:Object.values(bm),moves:m}}));
api.get('/reports/products',only('admin'),h(q=>P(`SELECT p.name,SUM(CASE v.type WHEN 'sale' THEN i.qty ELSE -i.qty END) qty,SUM(CASE v.type WHEN 'sale' THEN i.qty*i.price ELSE -i.qty*i.price END) revenue,SUM(CASE v.type WHEN 'sale' THEN i.qty*i.cost ELSE -i.qty*i.cost END) cost FROM invoice_items i JOIN invoices v ON v.id=i.invoice_id JOIN products p ON p.id=i.product_id WHERE v.shop_id=? AND v.type IN('sale','sale_return') AND v.date BETWEEN ? AND ? GROUP BY p.id ORDER BY revenue DESC`).all(q.u.shop,q.query.from||'0000',q.query.to||'9999').map(r=>({...r,profit:r.revenue-r.cost}))));
api.get('/reports/tax',only('admin'),h(q=>P(`SELECT substr(date,1,7) month,SUM(CASE type WHEN 'sale' THEN total-tax WHEN 'sale_return' THEN -(total-tax) ELSE 0 END) sales_net,SUM(CASE type WHEN 'sale' THEN tax WHEN 'sale_return' THEN -tax ELSE 0 END) tax_out,SUM(CASE type WHEN 'purchase' THEN tax WHEN 'purchase_return' THEN -tax ELSE 0 END) tax_in FROM invoices WHERE shop_id=? AND date BETWEEN ? AND ? GROUP BY month ORDER BY month`).all(q.u.shop,q.query.from||'0000',q.query.to||'9999')));
const stk=(b,pid)=>(P('SELECT qty FROM stock WHERE product_id=? AND branch_id=?').get(pid,b)||{qty:0}).qty;
const setQty=(pid,b,n)=>P('INSERT INTO stock VALUES(?,?,?) ON CONFLICT(product_id,branch_id) DO UPDATE SET qty=?').run(pid,b,n,n);
const mv=(q,b,pid,kind,delta,after,note)=>P('INSERT INTO stock_moves(shop_id,branch_id,product_id,kind,delta,after,note,user_id) VALUES(?,?,?,?,?,?,?,?)').run(q.u.shop,b,pid,kind,delta,after,String(note||'').slice(0,200),q.u.id);
const ownProd=(id,shop)=>{if(!P('SELECT 1 FROM products WHERE id=? AND shop_id=?').get(id,shop))throw err('صنف غير صالح')};
api.post('/stock/count',only('admin'),h(q=>{const{items,note}=q.body;if(!Array.isArray(items)||!items.length)throw err('لا توجد أصناف');const b=br(q);
 return db.transaction(()=>{let n=0;for(const i of items){const c=+i.qty;if(!(c>=0))throw err('كمية غير صالحة');ownProd(i.product_id,q.u.shop);const cur=stk(b,i.product_id);if(c===cur)continue;setQty(i.product_id,b,c);mv(q,b,i.product_id,'count',c-cur,c,note);n++}
  audit(q.u.shop,q.u.id,'stock_count',n+' items');return{changed:n}})()}));
api.post('/stock/transfer',only('admin'),h(q=>{const{from_branch,to_branch,items,note}=q.body;if(!Array.isArray(items)||!items.length||!from_branch||!to_branch||from_branch==to_branch)throw err('بيانات النقل غير صالحة');
 for(const x of [from_branch,to_branch])if(!P('SELECT 1 FROM branches WHERE id=? AND shop_id=?').get(x,q.u.shop))throw err('فرع غير صالح');
 return db.transaction(()=>{for(const i of items){const n=+i.qty;if(!(n>0))throw err('كمية غير صالحة');ownProd(i.product_id,q.u.shop);const a=stk(from_branch,i.product_id);if(a<n)throw err('الكمية غير كافية في الفرع المصدر');
  const t=stk(to_branch,i.product_id);setQty(i.product_id,from_branch,a-n);setQty(i.product_id,to_branch,t+n);mv(q,from_branch,i.product_id,'transfer_out',-n,a-n,note);mv(q,to_branch,i.product_id,'transfer_in',n,t+n,note)}
  audit(q.u.shop,q.u.id,'stock_transfer',from_branch+'->'+to_branch);return{ok:1}})()}));
api.get('/stock/moves',only('admin'),h(q=>P('SELECT m.*,(SELECT name FROM products WHERE id=m.product_id) product,(SELECT name FROM branches WHERE id=m.branch_id) branch FROM stock_moves m WHERE shop_id=? AND (?=0 OR branch_id=?) ORDER BY id DESC LIMIT ?').all(q.u.shop,+q.query.branch||0,+q.query.branch||0,Math.min(+q.query.limit||50,200))));
api.get('/paymethods',h(q=>{ensureMethods(q.u.shop);return P('SELECT * FROM pay_methods WHERE shop_id=? ORDER BY id').all(q.u.shop)}));
api.post('/paymethods',only('admin'),h(q=>{const n=String(q.body.name||'').trim().slice(0,40),k=['cash','bank','credit'].includes(q.body.kind)?q.body.kind:'cash';if(!n)throw err('الاسم مطلوب');ensureMethods(q.u.shop);
 if(P('SELECT 1 FROM pay_methods WHERE shop_id=? AND name=?').get(q.u.shop,n))throw err('الطريقة موجودة');return{id:P('INSERT INTO pay_methods(shop_id,name,kind) VALUES(?,?,?)').run(q.u.shop,n,k).lastInsertRowid}}));
api.delete('/paymethods/:id',only('admin'),h(q=>{P('DELETE FROM pay_methods WHERE id=? AND shop_id=?').run(q.params.id,q.u.shop)}));
api.post('/ledger',h(q=>{const{party_id,amt,note}=q.body;if(!(+amt>0)||!party_id)throw err('بيانات غير صالحة');ownParty(party_id,q.u.shop);
 return{id:P('INSERT INTO ledger(shop_id,branch_id,party_id,amt,note,date,user_id) VALUES(?,?,?,?,?,?,?)').run(q.u.shop,br(q),party_id,r2(+amt),String(note||'').slice(0,300),today(),q.u.id).lastInsertRowid}}));
api.delete('/ledger/:id',only('admin'),h(q=>{P('DELETE FROM ledger WHERE id=? AND shop_id=?').run(q.params.id,q.u.shop);audit(q.u.shop,q.u.id,'ledger_deleted',q.params.id)}));
api.get('/parties/:id/last-prices',h(q=>{ownParty(q.params.id,q.u.shop);const o={};for(const r of P("SELECT i.product_id,i.price FROM invoice_items i JOIN invoices v ON v.id=i.invoice_id WHERE v.party_id=? AND v.type='sale' ORDER BY v.id DESC").all(q.params.id))if(!(r.product_id in o))o[r.product_id]=r.price;return o}));
api.get('/dashboard',h(q=>{const s=q.u.shop,A=q.u.role==='admin',b=br(q),d=/^\d{4}-\d{2}-\d{2}$/.test(q.query.date||'')?q.query.date:today(),one=(sql,...a)=>P(sql).get(...a).x;
 const sales=day=>one("SELECT COALESCE(SUM(CASE type WHEN 'sale' THEN total WHEN 'sale_return' THEN -total ELSE 0 END),0) x FROM invoices WHERE shop_id=? AND branch_id=? AND date=?",s,b,day);
 const last7=[];for(let i=6;i>=0;i--){const day=addDays(d,-i);last7.push({date:day,total:r2(sales(day))})}
 let profit=null;if(A){const rev=one("SELECT COALESCE(SUM(CASE type WHEN 'sale' THEN total-tax WHEN 'sale_return' THEN -(total-tax) ELSE 0 END),0) x FROM invoices WHERE shop_id=? AND branch_id=? AND date=?",s,b,d),
  cg=one("SELECT COALESCE(SUM(CASE v.type WHEN 'sale' THEN i.qty*i.cost WHEN 'sale_return' THEN -i.qty*i.cost ELSE 0 END),0) x FROM invoice_items i JOIN invoices v ON v.id=i.invoice_id WHERE v.shop_id=? AND v.branch_id=? AND v.date=?",s,b,d),
  ex=one('SELECT COALESCE(SUM(amt),0) x FROM expenses WHERE shop_id=? AND branch_id=? AND date=?',s,b,d);profit=r2(rev-cg-ex)}
 const rc=[];P('SELECT id,type,no,date,at,total FROM invoices WHERE shop_id=? AND branch_id=? ORDER BY id DESC LIMIT 8').all(s,b).forEach(x=>rc.push({t:x.at||x.date,k:x.type,r:x.no,a:x.total}));
 if(A)P('SELECT date,at,cat,amt FROM expenses WHERE shop_id=? AND branch_id=? ORDER BY id DESC LIMIT 8').all(s,b).forEach(x=>rc.push({t:x.at||x.date,k:'expense',r:x.cat,a:x.amt}));
 P('SELECT p.date,p.at,p.type,p.amt,(SELECT name FROM parties WHERE id=p.party_id) party FROM payments p WHERE shop_id=? AND branch_id=? ORDER BY id DESC LIMIT 8').all(s,b).forEach(x=>rc.push({t:x.at||x.date,k:x.type==='customer'?'collect':'pay',r:x.party||'',a:x.amt}));
 rc.sort((x,y)=>String(y.t).localeCompare(String(x.t)));
 const sv=r2(one('SELECT COALESCE(SUM(st.qty*p.cost),0) x FROM stock st JOIN products p ON p.id=st.product_id WHERE p.shop_id=? AND st.branch_id=?',s,b));
 return{capital:sv,date:d,customers:one("SELECT COUNT(*) x FROM parties WHERE shop_id=? AND type='customer'",s),stock_value:r2(one('SELECT COALESCE(SUM(st.qty*p.cost),0) x FROM stock st JOIN products p ON p.id=st.product_id WHERE p.shop_id=? AND st.branch_id=?',s,b)),sales:last7[6].total,
  invoices:one("SELECT COUNT(*) x FROM invoices WHERE shop_id=? AND branch_id=? AND date=? AND type='sale'",s,b,d),profit,last7,recent:rc.slice(0,8)}}));
api.get('/reports/methods',only('admin'),h(q=>{ensureMethods(q.u.shop);const s=q.u.shop,a=q.query.from||'0000',z=q.query.to||'9999',bm={};
 const add=(n,x)=>{n=n||'نقدًا';const e=bm[n]||(bm[n]={name:n,in:0,out:0});if(x>0)e.in+=x;else e.out-=x};
 P('SELECT type,party_id,total,paid,pay_method FROM invoices WHERE shop_id=? AND date BETWEEN ? AND ?').all(s,a,z).forEach(x=>{if(x.type==='sale')add(x.pay_method,x.party_id?x.paid:x.total);else if(x.type==='purchase')add(x.pay_method,-(x.party_id?x.paid:x.total));else if(x.type==='sale_return'&&!x.party_id)add(x.pay_method,-x.total);else if(x.type==='purchase_return'&&!x.party_id)add(x.pay_method,x.total)});
 P('SELECT type,amt,method FROM payments WHERE shop_id=? AND date BETWEEN ? AND ?').all(s,a,z).forEach(x=>add(x.method,x.type==='customer'?x.amt:-x.amt));
 P('SELECT amt FROM expenses WHERE shop_id=? AND date BETWEEN ? AND ?').all(s,a,z).forEach(x=>add(null,-x.amt));
 const kd={};P('SELECT name,kind FROM pay_methods WHERE shop_id=?').all(s).forEach(x=>kd[x.name]=x.kind);
 return Object.values(bm).map(e=>({...e,in:r2(e.in),out:r2(e.out),kind:kd[e.name]||'cash',net:r2(e.in-e.out)}))}));
api.get('/banner',h(q=>{const m=P('SELECT v FROM meta WHERE k=?').get('banner:'+q.u.shop);return{banner:m?m.v:''}}));
api.put('/banner',only('admin'),h(q=>{const b=String(q.body.banner||'');if(b&&(!/^data:image\/(png|jpeg|webp);base64,/.test(b)||b.length>700000))throw err('صورة غير صالحة أو كبيرة');P('INSERT INTO meta VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=?').run('banner:'+q.u.shop,b,b)}));
const PUBF=process.env.LICENSE_PUB||path.join(__dirname,'license-pub.pem'),PUB=fs.existsSync(PUBF)?crypto.createPublicKey(fs.readFileSync(PUBF)):null;
const machineCode=()=>{const m=Object.values(os.networkInterfaces()).flat().find(i=>i&&!i.internal&&i.mac&&i.mac!=='00:00:00:00:00:00');return sha(os.hostname()+'|'+(m?m.mac:'')).slice(0,12).toUpperCase()};
const verifyKey=k=>{if(!PUB)throw err('التفعيل غير متاح: لا يوجد مفتاح عام للمزوّد في هذه النسخة');const[h,b,sg]=String(k||'').trim().split('.');if(h!=='ACCL1'||!b||!sg)throw err('مفتاح التفعيل غير صالح');
 const pl=Buffer.from(b,'base64url');let ok=false;try{ok=crypto.verify(null,pl,PUB,Buffer.from(sg,'base64url'))}catch(e){}if(!ok)throw err('مفتاح التفعيل غير صالح (توقيع خاطئ)');try{return JSON.parse(pl.toString())}catch(e){throw err('مفتاح التفعيل غير صالح')}};
api.get('/license/info',h(()=>({machine:machineCode(),enabled:!!PUB})));
api.post('/license/activate',only('admin'),h(q=>{const p=verifyKey(q.body.key);if(p.t!=='lic'||!(+p.days>0)||!p.n)throw err('مفتاح التفعيل غير صالح');
 if(p.machine&&p.machine!=='*'&&p.machine!==machineCode())throw err('هذا المفتاح مخصص لجهاز آخر');if(p.by&&p.by<today())throw err('انتهت مهلة تفعيل هذا المفتاح، اطلب مفتاحًا جديدًا');
 const um=P("SELECT v FROM meta WHERE k='used_keys'").get(),used=um?JSON.parse(um.v):[];if(used.includes(p.n))throw err('هذا المفتاح استُخدم من قبل');
 return db.transaction(()=>{const sh=P('SELECT expires FROM shops WHERE id=?').get(q.u.shop),base=sh.expires&&sh.expires>today()?sh.expires:today(),e=addDays(base,Math.round(+p.days));
  P("UPDATE shops SET expires=?,plan=?,status='active' WHERE id=?").run(e,String(p.plan||'standard').slice(0,30),q.u.shop);used.push(p.n);
  P("INSERT INTO meta VALUES('used_keys',?) ON CONFLICT(k) DO UPDATE SET v=?").run(JSON.stringify(used),JSON.stringify(used));audit(q.u.shop,q.u.id,'license_activated',p.n+' +'+p.days+'d -> '+e);return{expires:e,days:Math.round(+p.days)}})()}));
const lanUrls=()=>process.env.HOST==='0.0.0.0'?Object.values(os.networkInterfaces()).flat().filter(i=>i&&i.family==='IPv4'&&!i.internal).map(i=>'http://'+i.address+':'+(process.env.PORT||3000)):[];
api.post('/backup',only('admin'),(q,s)=>bk.run(db).then(f=>{audit(q.u.shop,q.u.id,'backup',path.basename(f));s.json({file:f})}).catch(e=>s.status(500).json({error:e.message})));
api.get('/backup/info',only('admin'),h(()=>({dir:bk.dir(),files:bk.list().slice(0,5),lan:lanUrls()})));
api.get('/license',h(q=>q.lic));
api.get('/shop',h(q=>P('SELECT id,name,legal_name,tax_id,address,phone,footer,logo,plan,expires,status FROM shops WHERE id=?').get(q.u.shop)));
api.put('/shop',only('admin'),h(q=>{const b=q.body;if(b.logo&&(!/^data:image\/(png|jpeg|webp);base64,/.test(b.logo)||b.logo.length>300000))throw err('شعار غير صالح');P('UPDATE shops SET name=COALESCE(?,name),legal_name=?,tax_id=?,address=?,phone=?,footer=?,logo=COALESCE(?,logo) WHERE id=?').run(b.name||null,b.legal_name||'',b.tax_id||'',b.address||'',b.phone||'',b.footer||'',b.logo??null,q.u.shop);audit(q.u.shop,q.u.id,'shop_updated')}));
api.get('/audit',only('admin'),h(q=>P('SELECT * FROM audit WHERE shop_id=? ORDER BY id DESC LIMIT 200').all(q.u.shop)));
api.put('/password',h(q=>{const u=P('SELECT * FROM users WHERE id=?').get(q.u.id);if(!bcrypt.compareSync(q.body.old||'',u.hash))throw err('كلمة المرور الحالية خاطئة',401);
 if((q.body.new||'').length<8)throw err('8 أحرف على الأقل');P('UPDATE users SET hash=?,tv=tv+1 WHERE id=?').run(bcrypt.hashSync(q.body.new,10),u.id);audit(q.u.shop,u.id,'password_changed');return{token:sign(P('SELECT * FROM users WHERE id=?').get(u.id))}}));
api.put('/users/:id/password',only('admin'),h(q=>{if((q.body.password||'').length<8)throw err('8 أحرف على الأقل');
 if(!P('UPDATE users SET hash=?,tv=tv+1 WHERE id=? AND shop_id=?').run(bcrypt.hashSync(q.body.password,10),q.params.id,q.u.shop).changes)throw err('مستخدم غير موجود',404);audit(q.u.shop,q.u.id,'user_password_reset',q.params.id)}));
if(process.env.BACKUP_KEY||LOCAL){const run=()=>bk.run(db).then(f=>console.log('backup',f)).catch(e=>console.error('backup error',e.message));setInterval(run,(+process.env.BACKUP_EVERY_HOURS||24)*36e5);setTimeout(run,LOCAL?20e3:60e3)}else console.warn('⚠️ BACKUP_KEY غير معرّف: النسخ الاحتياطي معطّل');
if(!process.env.ADMIN_KEY&&!LOCAL)console.warn('ℹ️ ADMIN_KEY غير معرّف: لوحة المزوّد /vendor معطّلة');
const PORT=process.env.PORT||3000,HOST=process.env.HOST,onUp=()=>{console.log('البرنامج يعمل على: http://localhost:'+PORT);if(LOCAL)lanUrls().forEach(u=>console.log('من أجهزة أخرى على الشبكة: '+u))};
const srv=HOST?app.listen(PORT,HOST,onUp):app.listen(PORT,onUp);
srv.on('error',e=>{console.error('تعذّر تشغيل الخادم:',e.message);if(!process.versions.electron)process.exit(1)});
module.exports={backupNow:()=>bk.run(db),close:()=>srv.close()};
