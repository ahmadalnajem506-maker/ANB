/*!
 * BankImportEngine v1.0.0
 * ─────────────────────────────────────────────────────────────────────────
 * مكتبة مستقلة تمامًا لاستيراد كشوف الحساب البنكية وتحويلها لنموذج معاملة
 * موحَّد - بلا أي اعتماد على أي تطبيق مضيف (لا تقرأ أي متغيّر عام من التطبيق
 * ولا تُعدِّل أي حالة تطبيق مباشرة). كل دالة/صنف هنا: بيانات تدخل → بيانات
 * تخرج، بلا أي أثر جانبي على الواجهة أو التخزين. التطبيق المضيف (أي تطبيق،
 * حاليًا أو مستقبلًا) هو من يقرر ماذا يفعل بالنتيجة (يحفظها، يعرضها، إلخ).
 *
 * الاعتماديات الوحيدة الخارجية (اختيارية، فقط لو استُخدمت الميزة المرتبطة):
 *   - XLSX (SheetJS)  → مطلوبة فقط لـ ExcelParser
 *   - DOMParser        → مطلوبة فقط لـ CAMT053Parser (متوفرة افتراضيًا بالمتصفح)
 *
 * الاستخدام الأساسي (الواجهة العليا الوحيدة اللي يحتاجها أغلب المستخدمين):
 *   const result = await BankImportEngine.ImportService.processFile(file, {
 *     cid: 'client123',
 *     bankKey: 'auto',              // أو 'ing' / 'abn' / ... لإجبار بنك معيّن
 *     existingTransactions: myExistingTxArray
 *   });
 *   // result = { bankKey, bankLabel, fileKind, allTxs, uniqueTxs, duplicateTxs,
 *   //            invalidCount, excludedPendingCount }
 *
 * الاستخدام المتقدّم: كل صنف (FileDetector, ParserFactory, ...) متاح مستقلًا
 * لمن يريد التحكّم بخطوة واحدة بمعزل عن البقية.
 * ─────────────────────────────────────────────────────────────────────────
 */
(function(root, factory){
  if(typeof module==='object' && module.exports){
    module.exports=factory(); // Node / CommonJS
  }else{
    root.BankImportEngine=factory(); // <script> عادي بالمتصفح
  }
})(typeof self!=='undefined'?self:this, function(){
  'use strict';

  // ═══════════════════════════════════════════════════════════════════
  // أدوات داخلية عامة (لا تُصدَّر مباشرة - تُستخدَم من كل الأصناف أدناه)
  // ═══════════════════════════════════════════════════════════════════
  function genId(){
    return Date.now().toString(36)+Math.random().toString(36).slice(2,10);
  }

  // يقسّم سطر CSV واحد لأعمدة، بتمييز تلقائي بين الفاصلة والفاصلة المنقوطة،
  // ومعاملة صحيحة للحقول المُقتبَسة (بما فيها فاصلة/فاصلة منقوطة داخل الاقتباس)
  function splitCSVLine(line){
    const sep=line.includes(';')?';':',';
    const res=[]; let cur='',inQ=false;
    for(let i=0;i<line.length;i++){
      const ch=line[i];
      if(ch==='"'){inQ=!inQ;}
      else if(ch===sep&&!inQ){res.push(cur);cur='';}
      else{cur+=ch;}
    }
    res.push(cur);
    return res.map(c=>c.replace(/"/g,''));
  }

  // يحوّل نص CSV خام كامل لمصفوفة صفوف (كل صف = مصفوفة أعمدة نصية)
  function textToRows(raw){
    return raw.split('\n').map(l=>l.trim()).filter(Boolean).map(splitCSVLine);
  }

  // DD-MM-YYYY أو DD/MM/YYYY أو YYYYMMDD (بلا فواصل) - الصيغ الهولندية الشائعة
  function parseDateNL(s){
    if(!s)return null;
    s=String(s).trim().replace(/"/g,'');
    if(/^\d{8}$/.test(s))return `${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}`;
    const m=s.match(/^(\d{1,2})[-/](\d{1,2})[-/](\d{4})$/);
    if(m)return `${m[3]}-${m[2].padStart(2,'0')}-${m[1].padStart(2,'0')}`;
    return parseDateISO(s);
  }
  // YYYY-MM-DD أو YYYY/MM/DD (تتجاهل أي وقت متبوع، الاستدعاء يُقصِّص الوقت مسبقًا عادةً)
  function parseDateISO(s){
    if(!s)return null;
    const m=String(s).trim().match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})$/);
    if(m)return `${m[1]}-${m[2].padStart(2,'0')}-${m[3].padStart(2,'0')}`;
    return null;
  }
  // Excel (Windows) epoch يبدأ 1899-12-30 - تحويل رقم تسلسلي لتاريخ فعلي
  function excelSerialToISODate(serial){
    const d=new Date(Math.round((Number(serial)-25569)*86400*1000));
    return isNaN(d.getTime())?null:d.toISOString().slice(0,10);
  }

  // نموذج المعاملة الموحَّد - كل parser يُنتج هذا الشكل بالضبط
  function makeUnifiedTx(cid,f){
    return{
      id:genId(),cid,
      bookingDate:f.bookingDate,valueDate:f.valueDate||f.bookingDate,
      description:f.description||'',counterpartyName:f.counterpartyName||'',
      iban:f.iban||'',ownIban:f.ownIban||'',
      amount:f.amount,currency:f.currency||'EUR',
      balance:(f.balance===undefined||f.balance===null||isNaN(f.balance))?null:f.balance,
      reference:f.reference||'',endToEndId:f.endToEndId||'',
      transactionType:f.transactionType||'',bankName:f.bankName
    };
  }

  // ═══════════════════════════════════════════════════════════════════
  // FileDetector — يكتشف نوع الملف ونوع المحتوى (بلا أي معرفة ببنك معيّن)
  // ═══════════════════════════════════════════════════════════════════
  class FileDetector{
    // نوع الملف من امتداده فقط - يحدّد كيف نقرأ الملف (نص أم ثنائي)
    static getFileKind(filename){
      const ext=(filename||'').toLowerCase().split('.').pop();
      if(ext==='xlsx'||ext==='xls')return 'excel';
      if(ext==='xml')return 'xml';
      return 'text'; // csv, txt, mt940, sta, 940, أو بلا امتداد معروف
    }
    // نوع المحتوى من النص الخام نفسه: 'mt940' | 'camt053' | 'csv' | null
    static detectContentFormat(raw){
      if(!raw)return null;
      if(/:20:/.test(raw)&&(/:61:/.test(raw)||/:60F:/.test(raw)||/:86:/.test(raw)))return 'mt940';
      if(/<(?:\w+:)?BkToCstmrStmt/.test(raw)||/<(?:\w+:)?Document[^>]*camt\.053/.test(raw))return 'camt053';
      return 'csv';
    }
    // يستخرج صف العنوان الأول كأعمدة نصية مطبَّعة (lowercase, بلا اقتباس) -
    // يُستخدَم كمُدخَل لـ ParserFactory.detectBank(cols)
    static extractHeaderColumns(raw){
      const firstLine=(raw.split('\n')[0]||'').replace(/\r$/,'');
      return splitCSVLine(firstLine).map(c=>c.trim().toLowerCase());
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // ملفات تعريف البنوك (Bank Profiles) — بيانات بحتة، لا صنف منفصل لكل بنك.
  // إضافة بنك جديد = إضافة ملف تعريف واحد هنا، بلا لمس أي محرك آخر.
  // كل ملف تعريف: اسم، دالة تحقق من العنوان (matchesHeader)، ودالة بناء
  // معاملة من صف أعمدة واحد (buildTx) - هذي بالضبط "منطق البنك" المطلوب
  // حصره داخل تعريفه الخاص بلا تسرّب لأي مكان آخر بالمحرك.
  // ⚠️ الترتيب بالمصفوفة يحدّد أولوية الفحص - الأكثر تفرُّدًا أولًا لتفادي
  // تصادم الكشف (نفس الدرس المُستفاد من خطأ حقيقي واجهناه مع ING/Rabobank)
  // ═══════════════════════════════════════════════════════════════════
  const BANK_PROFILES=[
    {
      key:'rabobank',label:'Rabobank',
      matchesHeader:c=>c.includes('iban/bban')||c.includes('tegenrekening iban/bban')||c.includes('naam tegenpartij')||c.includes('volgnr')||c.includes('saldo na trn'),
      buildTx(c){
        const bookingDate=parseDateNL(c[4]);
        const amount=parseFloat(String(c[6]||'').replace(',','.'))||0;
        if(!bookingDate||isNaN(amount)||amount===0)return null;
        const desc=[c[19],c[20],c[21]].map(s=>String(s||'').trim()).filter(Boolean).join(' · ');
        return{bookingDate,valueDate:parseDateNL(c[5])||bookingDate,
          description:(desc||String(c[9]||'').trim()).slice(0,150),counterpartyName:String(c[9]||'').trim(),
          iban:String(c[8]||'').trim(),ownIban:String(c[0]||'').trim(),amount,currency:String(c[1]||'EUR').trim(),
          balance:parseFloat(String(c[7]||'').replace(',','.'))||null,
          reference:String(c[15]||'').trim()||String(c[18]||'').trim(),bankName:'Rabobank'};
      }
    },
    {
      key:'abn',label:'ABN AMRO',
      matchesHeader:c=>c.includes('transactiedatum')&&c.includes('beginstand'),
      buildTx(c){
        const bookingDate=parseDateNL(c[0]);
        const amount=parseFloat(String(c[5]||'').replace(',','.'))||0;
        if(!bookingDate||isNaN(amount)||amount===0)return null;
        return{bookingDate,valueDate:parseDateNL(c[4])||bookingDate,
          description:String(c[6]||'').trim().slice(0,150),currency:String(c[1]||'EUR').trim(),
          balance:parseFloat(String(c[3]||'').replace(',','.'))||null,amount,bankName:'ABN'};
      }
    },
    {
      key:'knab',label:'Knab',
      matchesHeader:c=>c.includes('rekeningnummer')&&c.includes('creditdebet'),
      buildTx(c){
        const bookingDate=parseDateNL(c[1]);
        const cd=String(c[3]||'').trim().toLowerCase();
        const amt=parseFloat(String(c[4]||'').replace(',','.'))||0;
        // ⚠️ القيمة الحرفية الفعلية لعمود CreditDebet غير مؤكَّدة من ملف حقيقي -
        // تحقُّق دفاعي من عدة احتمالات شائعة بدل افتراض واحد فقط
        const isDebit=cd==='debit'||cd==='af'||cd==='d'||cd==='-';
        const amount=isDebit?-Math.abs(amt):Math.abs(amt);
        if(!bookingDate||isNaN(amount))return null;
        return{bookingDate,valueDate:parseDateNL(c[7])||bookingDate,
          description:String(c[9]||'').trim().slice(0,150),counterpartyName:String(c[6]||'').trim(),
          iban:String(c[5]||'').trim(),ownIban:String(c[0]||'').trim(),amount,currency:String(c[2]||'EUR').trim(),
          transactionType:String(c[10]||'').trim(),reference:String(c[14]||'').trim(),bankName:'Knab'};
      }
    },
    {
      key:'ing',label:'ING',
      matchesHeader:c=>c.includes('tegenrekening')||c.includes('mutatiesoort')||c.includes('mededelingen')||
        c.includes('naam / omschrijving')||c.includes('bedrag (eur)')||c.includes('debit/credit')||
        c.includes('name / description')||c.includes('transaction type')||(c.includes('datum')&&c.includes('bedrag')),
      buildTx(c){
        const bookingDate=parseDateNL(c[0]);
        const afbij=String(c[5]||'').trim().toLowerCase();
        const amt=parseFloat(String(c[6]||'').replace(',','.'))||0;
        const amount=(afbij==='af'||afbij==='debit')?-Math.abs(amt):Math.abs(amt);
        if(!bookingDate||isNaN(amount))return null;
        const notes=String(c[8]||'').trim();
        const refMatch=notes.match(/Reference:\s*(\S+)/i);
        return{bookingDate,description:(String(c[1]||'').trim()+(notes?'; '+notes:'')).slice(0,150),
          counterpartyName:String(c[1]||'').trim(),iban:String(c[3]||'').trim(),ownIban:String(c[2]||'').trim(),
          amount,currency:'EUR',transactionType:String(c[7]||'').trim(),
          reference:refMatch?refMatch[1]:'',bankName:'ING'};
      }
    },
    {
      key:'revolut',label:'Revolut',
      matchesHeader:c=>c.includes('started date')&&c.includes('completed date'),
      buildTx(c,ctx){
        const state=String(c[8]||'').trim().toUpperCase();
        if(state&&state!=='COMPLETED'){ctx.excludedPending++;return null;} // معلَّق/ملغى - ليس خطأ بيانات
        const bookingDate=parseDateISO(String(c[3]||'').trim().slice(0,10));
        const amount=parseFloat(c[5])||0;
        if(!bookingDate||isNaN(amount)||amount===0)return null;
        return{bookingDate,valueDate:parseDateISO(String(c[2]||'').trim().slice(0,10))||bookingDate,
          description:((c[0]?String(c[0]).trim()+': ':'')+String(c[4]||'').trim()).slice(0,150),
          amount,currency:String(c[7]||'EUR').trim(),balance:parseFloat(c[9])||null,
          transactionType:String(c[0]||'').trim(),bankName:'Revolut'};
      }
    },
    {
      key:'bunq',label:'Bunq',
      matchesHeader:c=>c.includes('counterparty')||(c.includes('amount')&&c.includes('account')&&c.includes('name')),
      buildTx(c){
        const bookingDate=parseDateISO(c[0]);
        const amount=parseFloat(String(c[1]||'').replace(',','.'))||0;
        if(!bookingDate||isNaN(amount)||amount===0)return null;
        return{bookingDate,description:(String(c[5]||'').trim()||String(c[4]||'').trim()).slice(0,150),
          counterpartyName:String(c[4]||'').trim(),iban:String(c[3]||'').trim(),ownIban:String(c[2]||'').trim(),
          amount,transactionType:String(c[6]||'').trim(),bankName:'Bunq'};
      }
    }
  ];
  const GENERIC_PROFILE={
    key:'generic',label:'Generic CSV',
    matchesHeader:()=>true, // احتياطي أخير دائمًا
    // ⚠️ العام يحتاج فهرسة أعمدة ديناميكية (لا مواقع ثابتة)، فيُبنى بمعرفة
    // العناوين نفسها - انظر GenericCSVProfileFor() أدناه
  };
  function genericProfileFor(headerCols){
    const norm=headerCols.map(h=>h.toLowerCase().replace(/[^a-z]/g,''));
    const dateIdx=norm.findIndex(h=>h.includes('dat'));
    const amtIdx=norm.findIndex(h=>h.includes('bedrag')||h.includes('amount')||h.includes('amt'));
    const descIdx=norm.findIndex(h=>h.includes('desc')||h.includes('omschr')||h.includes('memo')||h.includes('naam'));
    return{
      key:'generic',label:'Generic CSV',
      buildTx(c){
        if(dateIdx<0||amtIdx<0)return null;
        const bookingDate=parseDateNL(c[dateIdx])||parseDateISO(c[dateIdx]);
        const amount=parseFloat(String(c[amtIdx]||'').replace(',','.'))||0;
        if(!bookingDate||isNaN(amount)||amount===0)return null;
        return{bookingDate,description:(descIdx>=0?String(c[descIdx]||'').trim():'Import').slice(0,150),amount,bankName:'CSV'};
      }
    };
  }

  // ═══════════════════════════════════════════════════════════════════
  // ParserFactory — يختار البنك ويُجهِّز المُحلِّل المناسب. لا منطق تحليل هنا
  // نفسه، فقط التوجيه والاختيار.
  // ═══════════════════════════════════════════════════════════════════
  class ParserFactory{
    static listSupportedBanks(){
      return BANK_PROFILES.map(p=>({key:p.key,label:p.label}))
        .concat([{key:'mt940',label:'MT940'},{key:'camt053',label:'CAMT.053'}]);
    }
    // يكتشف مفتاح البنك من أعمدة عنوان مطبَّعة (lowercase) - يُعيد 'generic' لو ما طابق شيء
    static detectBankFromColumns(headerCols){
      const found=BANK_PROFILES.find(p=>p.matchesHeader(headerCols));
      return found?found.key:'generic';
    }
    static getProfile(bankKey,headerCols){
      if(bankKey==='generic')return genericProfileFor(headerCols||[]);
      return BANK_PROFILES.find(p=>p.key===bankKey)||genericProfileFor(headerCols||[]);
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // CSVParser — محرك عام واحد يُشغَّل بأي ملف تعريف بنك (Profile) - هذا هو
  // "لا منطق خاص ببنك خارج تعريفه" فعليًا: نفس المحرك بالضبط لكل البنوك،
  // فقط ملف التعريف يتغيّر. يُستخدَم أيضًا من ExcelParser (بلا تكرار كود).
  // ═══════════════════════════════════════════════════════════════════
  class CSVParser{
    parse(raw,bankKey,cid){
      return this.parseRows(textToRows(raw),bankKey,cid);
    }
    parseRows(rows,bankKey,cid){
      const headerCols=(rows[0]||[]).map(c=>String(c).toLowerCase().trim());
      const profile=ParserFactory.getProfile(bankKey,headerCols);
      const ctx={excludedPending:0};
      const txs=[];let skipped=0;
      for(let i=1;i<rows.length;i++){
        const c=rows[i];
        if(!c||c.length<2){skipped++;continue;}
        let fields;
        try{ fields=profile.buildTx(c,ctx); }
        catch(e){ skipped++; continue; }
        if(!fields){ if(ctx.excludedPending===0||i!==rows.length)skipped++; continue; }
        txs.push(makeUnifiedTx(cid,fields));
      }
      // ⚠️ نُصحِّح عدّاد skipped ليستثني حالات "معلَّق" المحسوبة أصلًا ضمن ctx.excludedPending
      skipped=Math.max(0,skipped-ctx.excludedPending);
      return{txs,skipped,excludedPending:ctx.excludedPending,bankKey:profile.key,bankLabel:profile.label};
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // ExcelParser — يقرأ .xlsx عبر SheetJS (XLSX) ثم يُسلِّم الصفوف لنفس
  // CSVParser بالضبط - صفر تكرار منطق بين مسار CSV ومسار Excel
  // ═══════════════════════════════════════════════════════════════════
  class ExcelParser{
    constructor(xlsxLib){
      // ⚠️ حقن مكتبة XLSX بدل الاعتماد على متغيّر عام - يسمح باستخدام المحرك
      // في أي سياق (Node، Worker، تطبيق آخر) بإمرار أي تنفيذ متوافق مع SheetJS API
      this.XLSX=xlsxLib||(typeof XLSX!=='undefined'?XLSX:null);
      if(!this.XLSX)throw new Error('ExcelParser requires the XLSX (SheetJS) library - pass it to the constructor or expose it as a global.');
    }
    parseArrayBuffer(buffer,bankKey,cid){
      const wb=this.XLSX.read(buffer,{type:'array',cellDates:false});
      const sheet=wb.Sheets[wb.SheetNames[0]];
      const rows=this.XLSX.utils.sheet_to_json(sheet,{header:1,raw:true,defval:''})
        .map(r=>r.map(c=>(c===undefined||c===null)?'':String(c)));
      return new CSVParser().parseRows(rows,bankKey,cid);
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // MT940Parser — صيغة SWIFT (معيار دولي، لا يخص بنكًا واحدًا)
  // ═══════════════════════════════════════════════════════════════════
  class MT940Parser{
    parse(raw,cid){
      const txs=[];let skipped=0;
      const ibanMatch=raw.match(/:25:([A-Z0-9]+)/);
      const ownIban=ibanMatch?ibanMatch[1].trim():'';
      const blocks=raw.split(/(?=:20:)/);
      for(const block of blocks){
        const stmts=block.split(/^:61:/m);
        for(let i=1;i<stmts.length;i++){
          try{
            const stmt=stmts[i];
            const dateMatch=stmt.match(/^(\d{6})/);
            const amtMatch=stmt.match(/^[\d]{6}[\d]{4}?([CD])(\d+),(\d*)/);
            if(!dateMatch||!amtMatch){skipped++;continue;}
            const yy=dateMatch[1].slice(0,2),mm=dateMatch[1].slice(2,4),dd=dateMatch[1].slice(4,6);
            const yr=parseInt(yy)<50?2000+parseInt(yy):1900+parseInt(yy);
            const bookingDate=`${yr}-${mm}-${dd}`;
            const sign=amtMatch[1]==='D'?-1:1;
            const amount=sign*parseFloat(amtMatch[2]+'.'+(amtMatch[3]||'00'));
            const descMatch=stmt.match(/:86:([\s\S]*?)(?=\n:|$)/);
            const rawDesc=descMatch?descMatch[1].replace(/\n/g,' ').trim():'';
            const ibanSub=rawDesc.match(/\/IBAN\/([A-Z0-9]+)/);
            const nameSub=rawDesc.match(/\/NAME\/([^/]+)/);
            const erefSub=rawDesc.match(/\/EREF\/([^/]+)/);
            const remiSub=rawDesc.match(/\/REMI\/([^/]+)/);
            const desc=(remiSub?remiSub[1].trim():rawDesc).slice(0,150)||'MT940 transaction';
            if(!bookingDate||isNaN(amount)){skipped++;continue;}
            txs.push(makeUnifiedTx(cid,{
              bookingDate,description:desc,counterpartyName:nameSub?nameSub[1].trim():'',
              iban:ibanSub?ibanSub[1].trim():'',ownIban,amount,
              endToEndId:erefSub?erefSub[1].trim():'',bankName:'MT940'
            }));
          }catch(e){skipped++;}
        }
      }
      return{txs,skipped,bankKey:'mt940',bankLabel:'MT940'};
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // CAMT053Parser — ISO 20022 XML (معيار أوروبي مفتوح، لا يخص بنكًا واحدًا)
  // ⚠️ لم يُختبَر على ملف حقيقي من أي بنك بعد - البنية العامة موثوقة (معيار
  // مفتوح موثَّق دوليًا) لكن بعض البنوك قد تضيف حقولًا اختيارية بطرق مختلفة
  // ═══════════════════════════════════════════════════════════════════
  class CAMT053Parser{
    constructor(domParserImpl){
      this.DOMParserImpl=domParserImpl||(typeof DOMParser!=='undefined'?DOMParser:null);
      if(!this.DOMParserImpl)throw new Error('CAMT053Parser requires a DOMParser implementation - pass it to the constructor or run in a browser.');
    }
    parse(raw,cid){
      const xml=new this.DOMParserImpl().parseFromString(raw,'text/xml');
      if(xml.getElementsByTagName('parsererror').length)throw new Error('Corrupted or invalid CAMT.053 XML file');

      const byTag=(el,tag)=>el?el.getElementsByTagName(tag):[];
      const first=(el,tag)=>{ const l=byTag(el,tag); return l&&l.length?l[0]:null; };
      const txt=(el,tag)=>{ const n=first(el,tag); return n&&n.textContent?n.textContent.trim():''; };
      const path=(el,...tags)=>{ let cur=el; for(const tg of tags){ cur=first(cur,tg); if(!cur)return null; } return cur; };
      const pathTxt=(el,...tags)=>{ const n=path(el,...tags); return n&&n.textContent?n.textContent.trim():''; };

      const txs=[];let skipped=0;
      const stmts=xml.getElementsByTagName('Stmt');
      for(let s=0;s<stmts.length;s++){
        const stmt=stmts[s];
        const ownIban=pathTxt(stmt,'Acct','Id','IBAN');
        const entries=byTag(stmt,'Ntry');
        for(let e=0;e<entries.length;e++){
          const ntry=entries[e];
          const amtNode=first(ntry,'Amt');
          const amt=parseFloat(amtNode&&amtNode.textContent?amtNode.textContent.trim():'')||0;
          const ccy=(amtNode&&amtNode.getAttribute&&amtNode.getAttribute('Ccy'))||'EUR';
          const isDebit=txt(ntry,'CdtDbtInd')==='DBIT';
          const amount=isDebit?-Math.abs(amt):Math.abs(amt);
          const bookingDate=pathTxt(ntry,'BookgDt','Dt')||pathTxt(ntry,'BookgDt','DtTm').slice(0,10);
          const valueDate=pathTxt(ntry,'ValDt','Dt')||pathTxt(ntry,'ValDt','DtTm').slice(0,10)||bookingDate;
          const acctSvcrRef=txt(ntry,'AcctSvcrRef')||txt(ntry,'NtryRef');
          const txDtls=path(ntry,'NtryDtls','TxDtls');
          const btch=path(ntry,'NtryDtls','Btch');
          let counterpartyName='',iban='',endToEndId='',remit='';
          if(txDtls){
            endToEndId=pathTxt(txDtls,'Refs','EndToEndId');
            remit=pathTxt(txDtls,'RmtInf','Ustrd');
            if(isDebit){ counterpartyName=pathTxt(txDtls,'RltdPties','Cdtr','Nm'); iban=pathTxt(txDtls,'RltdPties','CdtrAcct','Id','IBAN'); }
            else{ counterpartyName=pathTxt(txDtls,'RltdPties','Dbtr','Nm'); iban=pathTxt(txDtls,'RltdPties','DbtrAcct','Id','IBAN'); }
            // ⚠️ دفعات مجمَّعة حقيقية (batch): البنك يُبلِّغ عن الدفعة كلها كقيد
            // واحد بلا طرف دائن/مدين فردي - فقط الجهة المُبادِرة (InitgPty، غالبًا
            // نظام رواتب/دفع مثل Afas) - نستخدمها بديلًا معقولًا بدل ترك الحقل فارغًا
            if(!counterpartyName)counterpartyName=pathTxt(txDtls,'RltdPties','InitgPty','Nm');
          }
          // ⚠️ لو ما فيه نص وصف حقيقي (RmtInf/AddtlNtryInf) - شائع جدًا بالدفعات
          // المجمَّعة - نبني وصفًا مفيدًا من عدد المعاملات المُجمَّعة + الجهة
          // المُبادِرة، بدل سطر فارغ تمامًا بقائمة المعاملات (وُجِد هذا فعليًا
          // بملف حقيقي: قيد بقيمة €2,019,161.86 بلا أي وصف أو اسم طرف آخر إطلاقًا)
          let description=remit||txt(ntry,'AddtlNtryInf');
          if(!description&&btch){
            const nbOfTxs=pathTxt(btch,'NbOfTxs');
            description='Batch payment'+(nbOfTxs?' ('+nbOfTxs+' transactions)':'')+(counterpartyName?' via '+counterpartyName:'');
          }
          if(!bookingDate||isNaN(amount)||amount===0){skipped++;continue;}
          txs.push(makeUnifiedTx(cid,{
            bookingDate,valueDate,description:(description||'').slice(0,150),
            counterpartyName,iban,ownIban,amount,currency:ccy,
            reference:acctSvcrRef,endToEndId,bankName:'CAMT053'
          }));
        }
      }
      return{txs,skipped,bankKey:'camt053',bankLabel:'CAMT.053'};
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // TransactionValidator — فحص سلامة أي معاملة موحَّدة بمعزل عن مصدرها
  // ═══════════════════════════════════════════════════════════════════
  class TransactionValidator{
    static validate(tx){
      const errors=[];
      if(!tx.bookingDate||!/^\d{4}-\d{2}-\d{2}$/.test(tx.bookingDate))errors.push('Invalid or missing booking date');
      if(typeof tx.amount!=='number'||isNaN(tx.amount)||tx.amount===0)errors.push('Invalid or zero amount');
      if(!tx.cid)errors.push('Missing client/account id');
      return{valid:errors.length===0,errors};
    }
    // يُرجع {validTxs, invalidTxs, invalidCount} بمعزل عن التكرار (مسؤولية DuplicateChecker منفصلة تمامًا)
    static validateBatch(txs){
      const validTxs=[],invalidTxs=[];
      txs.forEach(tx=>{
        const r=TransactionValidator.validate(tx);
        if(r.valid)validTxs.push(tx); else invalidTxs.push({tx,errors:r.errors});
      });
      return{validTxs,invalidTxs,invalidCount:invalidTxs.length};
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // DuplicateChecker — كشف تكرار متدرّج الأولوية، بمعزل تام عن أي تخزين -
  // يستقبل "المعاملات الموجودة أصلًا" كمُعطى صريح، لا يقرأها من أي مكان عام
  // ═══════════════════════════════════════════════════════════════════
  class DuplicateChecker{
    // أولوية الحسم: endToEndId ← reference ← معرّف بنكي صريح (لو توفَّر لاحقًا
    // من أي مصدر) ← بصمة احتياطية (تاريخ+مبلغ+أول 20 حرف من الوصف)
    static getKey(tx){
      if(tx.endToEndId)return 'e2e:'+tx.endToEndId;
      if(tx.reference)return 'ref:'+tx.reference;
      if(tx.bankTxId)return 'btx:'+tx.bankTxId;
      return 'fp:'+tx.bookingDate+'|'+tx.amount+'|'+(tx.description||'').slice(0,20);
    }
    // يُعيد {uniqueTxs, duplicateTxs} - existingTxs أي مصفوفة معاملات موحَّدة
    // (أو حتى مصفوفة نصوص مفاتيح جاهزة، تُمرَّر كـ existingKeys بدلًا منها)
    static partition(newTxs,existingTxs){
      const existingKeys=new Set((existingTxs||[]).map(t=>typeof t==='string'?t:DuplicateChecker.getKey(t)));
      const uniqueTxs=[],duplicateTxs=[];
      newTxs.forEach(tx=>{
        if(existingKeys.has(DuplicateChecker.getKey(tx)))duplicateTxs.push(tx);
        else uniqueTxs.push(tx);
      });
      return{uniqueTxs,duplicateTxs};
    }
  }

  // ═══════════════════════════════════════════════════════════════════
  // ImportService — الواجهة العليا الوحيدة الموصى باستخدامها من أي تطبيق
  // مضيف. تُنسِّق بين كل الأصناف أعلاه، وتُعيد نتيجة واحدة جاهزة للعرض.
  // بلا أي أثر جانبي: لا تحفظ شيئًا، لا تستدعي أي واجهة - فقط تُعيد بيانات.
  // ═══════════════════════════════════════════════════════════════════
  class ImportService{
    /**
     * @param {File} file - كائن File من واجهة رفع الملفات بالمتصفح
     * @param {Object} opts
     * @param {string} opts.cid - معرّف العميل/الحساب (يُرفَق بكل معاملة)
     * @param {string} [opts.bankKey='auto'] - 'auto' أو مفتاح بنك محدَّد لإجبار مُحلِّل معيّن
     * @param {Array}  [opts.existingTransactions=[]] - معاملات موجودة مسبقًا لفحص التكرار
     * @param {Object} [opts.xlsxLib] - مكتبة XLSX (اختياري، لو غير متوفرة كمتغيّر عام)
     * @param {Object} [opts.domParserImpl] - تنفيذ DOMParser (اختياري، لو خارج متصفح)
     * @returns {Promise<Object>} { bankKey, bankLabel, fileKind, allTxs, uniqueTxs,
     *                              duplicateTxs, invalidCount, excludedPendingCount }
     */
    static processFile(file,opts){
      opts=opts||{};
      const cid=opts.cid;
      const bankKeyOverride=opts.bankKey||'auto';
      const existingTransactions=opts.existingTransactions||[];
      const fileKind=FileDetector.getFileKind(file.name);

      return new Promise((resolve,reject)=>{
        const reader=new FileReader();
        reader.onerror=()=>reject(new Error('Could not read file'));
        reader.onload=e=>{
          try{
            let result;
            if(fileKind==='excel'){
              const excelParser=new ExcelParser(opts.xlsxLib);
              const bankKey=bankKeyOverride!=='auto'?bankKeyOverride:'generic'; // يُحسَم فعليًا داخل parseRows إن كان 'generic' بلا تعريف صريح
              result=excelParser.parseArrayBuffer(e.target.result,bankKeyOverride!=='auto'?bankKeyOverride:ImportService._detectFromRows(e.target.result,opts.xlsxLib),cid);
            }else{
              const raw=e.target.result;
              const contentFormat=FileDetector.detectContentFormat(raw);
              if(contentFormat==='mt940'){
                result=new MT940Parser().parse(raw,cid);
              }else if(contentFormat==='camt053'){
                result=new CAMT053Parser(opts.domParserImpl).parse(raw,cid);
              }else{
                const headerCols=FileDetector.extractHeaderColumns(raw);
                const bankKey=bankKeyOverride!=='auto'?bankKeyOverride:ParserFactory.detectBankFromColumns(headerCols);
                result=new CSVParser().parse(raw,bankKey,cid);
              }
            }
            const {validTxs,invalidCount:extraInvalid}=TransactionValidator.validateBatch(result.txs);
            const{uniqueTxs,duplicateTxs}=DuplicateChecker.partition(validTxs,existingTransactions);
            resolve({
              bankKey:result.bankKey,bankLabel:result.bankLabel,fileKind,
              allTxs:result.txs,uniqueTxs,duplicateTxs,
              invalidCount:(result.skipped||0)+extraInvalid,
              excludedPendingCount:result.excludedPending||0
            });
          }catch(err){ reject(err); }
        };
        if(fileKind==='excel')reader.readAsArrayBuffer(file); else reader.readAsText(file);
      });
    }
    // مساعد داخلي: يكتشف البنك من صف عنوان ملف Excel قبل التحليل الفعلي
    static _detectFromRows(buffer,xlsxLib){
      const XLSXRef=xlsxLib||(typeof XLSX!=='undefined'?XLSX:null);
      if(!XLSXRef)return 'generic';
      const wb=XLSXRef.read(buffer,{type:'array',cellDates:false});
      const sheet=wb.Sheets[wb.SheetNames[0]];
      const rows=XLSXRef.utils.sheet_to_json(sheet,{header:1,raw:true,defval:''});
      const headerCols=(rows[0]||[]).map(c=>String(c).toLowerCase().trim());
      return ParserFactory.detectBankFromColumns(headerCols);
    }
  }

  return{
    FileDetector,ParserFactory,CSVParser,ExcelParser,MT940Parser,CAMT053Parser,
    TransactionValidator,DuplicateChecker,ImportService,
    // مُصدَّرة للاختبار/التوسّع المتقدّم فقط - الاستخدام العادي لا يحتاجها مباشرة
    _internal:{genId,splitCSVLine,textToRows,parseDateNL,parseDateISO,excelSerialToISODate,makeUnifiedTx,BANK_PROFILES}
  };
});
