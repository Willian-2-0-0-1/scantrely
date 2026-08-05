// ════════════════════════════════════════════════════════════════════════
//  GENERATORS MODULE v2 — bulk + mask + global person
// ════════════════════════════════════════════════════════════════════════
'use strict';

const GEN_MODULES = [
  { id:'cpf',       icon:'🪪', label:'Gerador de CPF' },
  { id:'cnpj',      icon:'🏢', label:'Gerador de CNPJ' },
  { id:'rg',        icon:'📄', label:'Gerador de RG' },
  { id:'cep',       icon:'📮', label:'Gerador de CEP' },
  { id:'pis',       icon:'💼', label:'Gerador de PIS/PASEP' },
  { id:'renavam',   icon:'🚗', label:'Gerador de RENAVAM' },
  { id:'cnh',       icon:'🪪', label:'Gerador de CNH' },
  { id:'titulo',    icon:'🗳️', label:'Gerador Título de Eleitor' },
  { id:'ie',        icon:'🏪', label:'Gerador Inscrição Estadual' },
  { id:'cartao',    icon:'💳', label:'Gerador Cartão de Crédito' },
  { id:'placa',     icon:'🚘', label:'Gerador Placa de Veículos' },
  { id:'veiculo',   icon:'🚙', label:'Gerador de Veículos' },
  { id:'conta',     icon:'🏦', label:'Gerador de Conta Bancária' },
  { id:'certidao',  icon:'📜', label:'Gerador de Certidões' },
  { id:'pessoa',    icon:'👤', label:'Gerador de Pessoas' },
  { id:'empresa',   icon:'🏭', label:'Gerador de Empresas' },
  { id:'curriculo', icon:'📋', label:'Gerador de Currículo' },
  { id:'nome',      icon:'✍️', label:'Gerador de Nomes' },
  { id:'nick',      icon:'🎮', label:'Gerador de Nicks' },
  { id:'numeros',   icon:'🔢', label:'Gerador de Números Aleatórios' },
  { id:'senha',     icon:'🔑', label:'Gerador de Senha' },
];

let _genActive = 'cpf';

// ─── Utilitários ─────────────────────────────────────────────────────
const _rnd  = (a,b) => Math.floor(Math.random()*(b-a+1))+a;
const _pick = arr  => arr[_rnd(0,arr.length-1)];
const _pad  = (n,l)=> String(n).padStart(l,'0');
const _esc  = s    => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

function _mod11(digits, weights) {
  const s = digits.reduce((a,d,i)=>a+d*weights[i],0);
  const r = s%11; return r<2?0:11-r;
}
function _copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(()=>{
    const t=document.createElement('textarea');t.value=text;
    document.body.appendChild(t);t.select();document.execCommand('copy');
    document.body.removeChild(t);
  });
}

// ════════════════════════════════════════════════════════════════════════
//  ALGORITMOS DE DOCUMENTOS
// ════════════════════════════════════════════════════════════════════════

function _genCPF(m=true){
  const d=Array.from({length:9},()=>_rnd(0,9));
  const d10=_mod11(d,[10,9,8,7,6,5,4,3,2]);
  const d11=_mod11([...d,d10],[11,10,9,8,7,6,5,4,3,2]);
  const n=[...d,d10,d11].join('');
  return m?n.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/,'$1.$2.$3-$4'):n;
}
function _genCNPJ(m=true){
  const d=Array.from({length:12},()=>_rnd(0,9));
  const d13=_mod11(d,[5,4,3,2,9,8,7,6,5,4,3,2]);
  const d14=_mod11([...d,d13],[6,5,4,3,2,9,8,7,6,5,4,3,2]);
  const n=[...d,d13,d14].join('');
  return m?n.replace(/(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})/,'$1.$2.$3/$4-$5'):n;
}
function _genRG(m=true){
  const d=Array.from({length:8},()=>_rnd(0,9)); d[0]=_rnd(1,9);
  const s=d.reduce((a,v,i)=>a+v*[2,3,4,5,6,7,8,9][i],0);
  const r=s%11; const c=r===0?'0':r===1?'X':String(11-r);
  if(!m) return d.join('')+c;
  return d.join('').replace(/(\d{2})(\d{3})(\d{3})/,'$1.$2.$3')+'-'+c;
}
const _CEP_RANGES=[[1000,9999,'SP','São Paulo'],[20000,28999,'RJ','Rio de Janeiro'],[29000,29999,'ES','Espírito Santo'],[30000,39999,'MG','Minas Gerais'],[40000,48999,'BA','Bahia'],[50000,56999,'PE','Pernambuco'],[60000,63999,'CE','Ceará'],[70000,77999,'DF','Distrito Federal'],[78000,78999,'MT','Mato Grosso'],[79000,79999,'MS','Mato Grosso do Sul'],[80000,87999,'PR','Paraná'],[88000,89999,'SC','Santa Catarina'],[90000,99999,'RS','Rio Grande do Sul']];
function _genCEP(m=true){
  const [mn,mx,uf,est]=_pick(_CEP_RANGES);
  const p=_pad(_rnd(mn,mx),5),s=_pad(_rnd(0,999),3);
  return m?`${p}-${s} (${uf} – ${est})`:`${p}${s}`;
}
function _genPIS(m=true){
  const d=Array.from({length:10},()=>_rnd(0,9));
  const c=_mod11(d,[3,2,9,8,7,6,5,4,3,2]);
  const n=[...d,c].join('');
  return m?n.replace(/(\d{3})(\d{5})(\d{2})(\d{1})/,'$1.$2.$3-$4'):n;
}
function _genRENAVAM(m=true){
  const b=Array.from({length:8},()=>_rnd(0,9));
  const c=_mod11([0,0,...b],[3,2,9,8,7,6,5,4,3,2]);
  const n=[...b,c].join('');
  return m?n.replace(/(\d{4})(\d{4})(\d{1})/,'$1.$2-$3'):n;
}
function _genCNH(){
  const d=Array.from({length:9},()=>_rnd(0,9));
  const d1=d.reduce((a,v,i)=>a+v*(9-i),0)%11; const v1=d1>=10?0:d1;
  const d2=d.reduce((a,v,i)=>a+v*(1+i),0)%11; const v2=d2>=10?0:d2;
  return [...d,v1,v2].join('');
}
const _UF_CODES={SP:1,MG:2,RJ:3,RS:4,BA:5,PR:6,CE:7,PE:8,SC:9,GO:10,MA:11,PB:12,PA:13,ES:14,PI:15,RN:16,AL:17,MT:18,MS:19,DF:20,SE:21,AM:22,RO:23,AC:24,AP:25,RR:26,TO:27};
const _UF_LIST=Object.keys(_UF_CODES);
function _genTitulo(m=true){
  const uf=_pick(_UF_LIST),code=_UF_CODES[uf],seq=_pad(_rnd(1,99999999),8),st=_pad(code,2);
  const digs=(seq+st).split('').map(Number);
  let s1=digs.slice(0,8).reduce((a,v,i)=>a+v*[2,3,4,5,6,7,8,9][i],0);
  let d1=s1%11; if(d1===0)d1=code<=9?0:1; else if(d1===1)d1=code<=9?1:0; else d1=11-d1;
  let s2=digs[8]*7+digs[9]*8+d1*9; let d2=s2%11;
  if(d2===0)d2=code<=9?0:1; else if(d2===1)d2=code<=9?1:0; else d2=11-d2;
  const n=seq+st+d1+d2;
  return m?n.replace(/(\d{4})(\d{4})(\d{2})(\d{2})/,'$1 $2 $3 $4'):n;
}
const _IE_STATES=['SP','RJ','MG','PR','SC','RS','BA','PE','CE','GO','DF'];
function _genIE(uf='SP',m=true){
  const d=Array.from({length:8},()=>_rnd(0,9)); d[0]=_rnd(1,9);
  const w=[1,3,1,3,1,3,1,3]; let sum=0;
  d.forEach((v,i)=>{const p=v*w[i];sum+=p>9?Math.floor(p/10)+p%10:p;});
  const d9=(10-(sum%10))%10;
  const n=[...d,d9,_rnd(0,9),_rnd(0,9),_rnd(0,9)].join('');
  return m?n.replace(/(\d{3})(\d{3})(\d{3})(\d{3})/,'$1.$2.$3/$4'):n;
}
const _CARDS=[{n:'Visa',p:['4'],l:16},{n:'Mastercard',p:['51','52','53','54','55'],l:16},{n:'Elo',p:['6362970','636368','438935','504175'],l:16},{n:'Hipercard',p:['606282'],l:16},{n:'Amex',p:['34','37'],l:15}];
function _luhn(n){let s=0,a=false;for(let i=n.length-1;i>=0;i--){let v=n[i];if(a){v*=2;if(v>9)v-=9;}s+=v;a=!a;}return(10-s%10)%10;}
function _genCartao(m=true){
  const b=_pick(_CARDS),pfx=_pick(b.p).split('').map(Number);
  const n=[...pfx]; while(n.length<b.l-1)n.push(_rnd(0,9)); n.push(_luhn(n));
  const s=n.join('');
  const fmt=b.l===15?s.replace(/(\d{4})(\d{6})(\d{5})/,'$1 $2 $3'):s.replace(/(\d{4})(\d{4})(\d{4})(\d{4})/,'$1 $2 $3 $4');
  const mo=_pad(_rnd(1,12),2),yr=_rnd(new Date().getFullYear()+1,new Date().getFullYear()+5);
  const cvv=_pad(_rnd(0,b.l===15?9999:999),b.l===15?4:3);
  return m?`${b.n} | ${fmt} | ${mo}/${yr} | CVV: ${cvv}`:`${b.n}|${s}|${mo}/${yr}|${cvv}`;
}
const _LS='ABCDEFGHIJKLMNOPQRSTUVWXYZ';
function _genPlaca(tipo=null,m=true){
  const L=()=>_LS[_rnd(0,25)],D=()=>_rnd(0,9);
  const ms=tipo==='mercosul'||(tipo===null&&Math.random()>.5);
  const r=ms?`${L()}${L()}${L()}${D()}${L()}${D()}${D()}`:`${L()}${L()}${L()}${D()}${D()}${D()}${D()}`;
  return m?(ms?r:`${r.slice(0,3)}-${r.slice(3)}`):r;
}
const _MARCAS=['Volkswagen','Fiat','Chevrolet','Ford','Toyota','Honda','Hyundai','Renault','Jeep','Nissan'];
const _MODELOS={Volkswagen:['Gol','Polo','Virtus','T-Cross','Taos'],Fiat:['Strada','Uno','Mobi','Pulse','Cronos'],Chevrolet:['Onix','Tracker','S10','Spin'],Ford:['Ka','EcoSport','Ranger'],Toyota:['Corolla','Hilux','SW4','Yaris'],Honda:['HR-V','City','Civic','CR-V'],Hyundai:['HB20','Creta','Tucson'],Renault:['Kwid','Sandero','Logan','Duster'],Jeep:['Renegade','Compass'],Nissan:['Kicks','Versa','Frontier']};
const _CORES=['Branco','Prata','Preto','Cinza','Vermelho','Azul','Verde','Bege','Marrom'];
const _COMB=['Flex (Álcool/Gasolina)','Gasolina','Diesel','Elétrico','Híbrido'];
function _genVeiculo(){const m=_pick(_MARCAS);return{marca:m,modelo:_pick(_MODELOS[m]),ano:_rnd(2000,2025),cor:_pick(_CORES),combustivel:_pick(_COMB),placa:_genPlaca()};}
const _BANCOS=[{c:'001',n:'Banco do Brasil'},{c:'033',n:'Santander'},{c:'104',n:'Caixa Econômica Federal'},{c:'237',n:'Bradesco'},{c:'341',n:'Itaú'},{c:'260',n:'Nubank'},{c:'077',n:'Banco Inter'},{c:'336',n:'Banco C6'},{c:'208',n:'BTG Pactual'},{c:'212',n:'Banco Original'}];
function _genConta(){const b=_pick(_BANCOS);return{banco:`${b.c} - ${b.n}`,agencia:`${_pad(_rnd(1000,9999),4)}-${_rnd(0,9)}`,conta:`${_pad(_rnd(10000,999999),6)}-${_rnd(0,9)}`,tipo:_pick(['Corrente','Poupança','Salário'])};}
function _genCertidao(){return{tipo:_pick(['Nascimento','Casamento','Óbito']),matricula:`${_pad(_rnd(1,99999),5)} ${_pad(_rnd(1,99),2)} ${_rnd(1970,2024)} 2 ${_pad(_rnd(1,99),2)} ${_pad(_rnd(1,9999),4)} ${_rnd(100,999)} ${_pad(_rnd(10000,99999),5)}`,cartorio:_pick(['1º Ofício de Registro Civil','2º Ofício de Registro Civil','Cartório Paz e Bem']),uf:_pick(_UF_LIST),data:`${_pad(_rnd(1,28),2)}/${_pad(_rnd(1,12),2)}/${_rnd(1970,2024)}`};}
function _genSenha(l=16,lo=true,up=true,nu=true,sy=true){let c='';const p=[];if(lo){c+='abcdefghijklmnopqrstuvwxyz';p.push('abcdefghijklmnopqrstuvwxyz');}if(up){c+='ABCDEFGHIJKLMNOPQRSTUVWXYZ';p.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');}if(nu){c+='0123456789';p.push('0123456789');}if(sy){c+='!@#$%^&*()_+-=[]{}|;:,.<>?';p.push('!@#$%^&*()_+-=[]{}|;:,.<>?');}if(!c)c='abcdefghijklmnopqrstuvwxyz0123456789';let pw=p.map(x=>x[_rnd(0,x.length-1)]).join('');while(pw.length<l)pw+=c[_rnd(0,c.length-1)];return pw.split('').sort(()=>Math.random()-.5).join('').slice(0,l);}

// ════════════════════════════════════════════════════════════════════════
//  DADOS GLOBAIS — PESSOA COMPLETA (20 países)
// ════════════════════════════════════════════════════════════════════════

const _PAISES = {
  BR:{nome:'Brasil',           bandeira:'🇧🇷',moeda:'BRL (R$)',  doc:'CPF',fone:'+55 (XX) 9XXXX-XXXX',
    mNomes:['Miguel','Arthur','Davi','Gabriel','Lucas','Matheus','João','Pedro','Enzo','Lorenzo','Gustavo','Rafael','Henrique','Samuel','Felipe'],
    fNomes:['Alice','Sofia','Helena','Valentina','Laura','Isabella','Manuela','Júlia','Heloísa','Luíza','Maria','Beatriz','Letícia','Ana','Clara'],
    sobs:['Silva','Santos','Oliveira','Souza','Rodrigues','Ferreira','Alves','Lima','Gomes','Costa','Ribeiro','Martins','Carvalho','Almeida','Pereira','Nascimento','Barbosa','Gonçalves','Moreira','Castro'],
    cidades:['São Paulo','Rio de Janeiro','Belo Horizonte','Salvador','Fortaleza','Curitiba','Manaus','Recife','Porto Alegre','Belém'],
    estados:['SP','RJ','MG','BA','CE','PR','AM','PE','RS','PA'],
    zip:'NNNNN-NNN',ruas:['Rua das Flores','Av. Paulista','Rua do Sol','Al. Santos','Av. Brasil']},
  US:{nome:'Estados Unidos',   bandeira:'🇺🇸',moeda:'USD ($)',   doc:'SSN',fone:'+1 (XXX) XXX-XXXX',
    mNomes:['James','John','Robert','Michael','William','David','Richard','Joseph','Thomas','Charles','Christopher','Daniel','Matthew','Anthony','Mark'],
    fNomes:['Mary','Patricia','Jennifer','Linda','Barbara','Elizabeth','Susan','Jessica','Sarah','Karen','Lisa','Nancy','Betty','Margaret','Sandra'],
    sobs:['Smith','Johnson','Williams','Brown','Jones','Garcia','Miller','Davis','Wilson','Moore','Taylor','Anderson','Thomas','Jackson','White'],
    cidades:['New York','Los Angeles','Chicago','Houston','Phoenix','Philadelphia','San Antonio','San Diego','Dallas','San Jose'],
    estados:['NY','CA','TX','FL','IL','PA','OH','GA','NC','MI'],
    zip:'NNNNN',ruas:['Main St','Oak Ave','Maple Dr','Cedar Ln','Park Blvd']},
  GB:{nome:'Reino Unido',      bandeira:'🇬🇧',moeda:'GBP (£)',   doc:'NIN',fone:'+44 XXXX XXXXXX',
    mNomes:['Oliver','Harry','George','Noah','Jack','Charlie','Jacob','Freddie','Alfie','Leo','Oscar','William','Thomas','Ethan','James'],
    fNomes:['Olivia','Amelia','Isla','Ava','Mia','Isabella','Sophia','Grace','Lily','Freya','Evie','Poppy','Ella','Emily','Chloe'],
    sobs:['Smith','Jones','Williams','Taylor','Brown','Davies','Evans','Wilson','Thomas','Roberts','Johnson','Walker','Wright','Robinson','Thompson'],
    cidades:['London','Birmingham','Manchester','Leeds','Glasgow','Sheffield','Liverpool','Edinburgh','Bristol','Cardiff'],
    estados:['England','Scotland','Wales','Northern Ireland'],
    zip:'XX XX XXX',ruas:['High Street','Church Road','Station Road','Park Avenue','Victoria Street']},
  DE:{nome:'Alemanha',         bandeira:'🇩🇪',moeda:'EUR (€)',   doc:'Personalausweis',fone:'+49 XXX XXXXXXX',
    mNomes:['Leon','Paul','Jonas','Finn','Elias','Noah','Ben','Luca','Felix','Lukas','Maximilian','Julian','Moritz','Tim','Jan'],
    fNomes:['Emma','Mia','Hannah','Sophia','Emilia','Lena','Anna','Leonie','Marie','Lea','Clara','Laura','Lisa','Jana','Lara'],
    sobs:['Müller','Schmidt','Schneider','Fischer','Weber','Meyer','Wagner','Becker','Schulz','Hoffmann','Schäfer','Koch','Bauer','Richter','Klein'],
    cidades:['Berlin','Hamburg','München','Köln','Frankfurt','Stuttgart','Düsseldorf','Leipzig','Dortmund','Essen'],
    estados:['Bayern','NRW','BW','Niedersachsen','Hessen','Sachsen','Berlin','Hamburg'],
    zip:'NNNNN',ruas:['Hauptstraße','Schillerstraße','Bahnhofstraße','Gartenstraße','Bergstraße']},
  FR:{nome:'França',           bandeira:'🇫🇷',moeda:'EUR (€)',   doc:'CNI',fone:'+33 X XX XX XX XX',
    mNomes:['Gabriel','Raphaël','Lucas','Léo','Hugo','Louis','Arthur','Noah','Ethan','Liam','Antoine','Thomas','Maxime','Alexandre','Nicolas'],
    fNomes:['Emma','Jade','Léa','Manon','Inès','Chloé','Camille','Lucie','Zoé','Clara','Pauline','Marie','Jeanne','Alice','Anaïs'],
    sobs:['Martin','Bernard','Thomas','Petit','Robert','Richard','Durand','Dubois','Moreau','Laurent','Simon','Michel','Lefebvre','Leroy','Roux'],
    cidades:['Paris','Marseille','Lyon','Toulouse','Nice','Nantes','Strasbourg','Montpellier','Bordeaux','Lille'],
    estados:['Île-de-France','PACA','Auvergne-Rhône-Alpes','Occitanie','Normandie'],
    zip:'NNNNN',ruas:['Rue de la Paix','Avenue Victor Hugo','Rue du Commerce','Boulevard Saint-Germain']},
  ES:{nome:'Espanha',          bandeira:'🇪🇸',moeda:'EUR (€)',   doc:'DNI',fone:'+34 XXX XXX XXX',
    mNomes:['Alejandro','Daniel','Pablo','Carlos','Javier','David','Adrián','Sergio','Miguel','Iván','Diego','Marcos','Mario','Alberto','Luis'],
    fNomes:['Lucía','María','Paula','Laura','Marta','Sara','Elena','Noa','Sofía','Claudia','Valeria','Andrea','Alba','Carla','Ana'],
    sobs:['García','Martínez','López','Sánchez','González','Pérez','Rodríguez','Fernández','Torres','Ramírez','Flores','Herrera','Díaz','Ruiz','Moreno'],
    cidades:['Madrid','Barcelona','Valencia','Sevilla','Zaragoza','Málaga','Murcia','Bilbao','Alicante','Córdoba'],
    estados:['Madrid','Cataluña','Andalucía','Comunidad Valenciana','País Vasco'],
    zip:'NNNNN',ruas:['Calle Mayor','Gran Vía','Paseo de la Castellana','Avenida de América']},
  IT:{nome:'Itália',           bandeira:'🇮🇹',moeda:'EUR (€)',   doc:'Carta d\'Identità',fone:'+39 XXX XXXXXXX',
    mNomes:['Francesco','Alessandro','Lorenzo','Matteo','Andrea','Luca','Marco','Davide','Gabriele','Riccardo','Leonardo','Filippo','Nicola','Simone','Alberto'],
    fNomes:['Sofia','Giulia','Aurora','Alice','Martina','Giorgia','Chiara','Beatrice','Emma','Valentina','Elisa','Federica','Sara','Francesca','Laura'],
    sobs:['Rossi','Russo','Ferrari','Esposito','Bianchi','Romano','Colombo','Ricci','Marino','Greco','Bruno','Gallo','Conti','De Luca','Costa'],
    cidades:['Roma','Milano','Napoli','Torino','Palermo','Genova','Bologna','Firenze','Bari','Venezia'],
    estados:['Lazio','Lombardia','Campania','Piemonte','Toscana','Veneto'],
    zip:'NNNNN',ruas:['Via Roma','Corso Italia','Viale Mazzini','Piazza Garibaldi']},
  PT:{nome:'Portugal',         bandeira:'🇵🇹',moeda:'EUR (€)',   doc:'Cartão de Cidadão',fone:'+351 XXX XXX XXX',
    mNomes:['João','Pedro','Rodrigo','André','Miguel','Tiago','Diogo','Rui','Nuno','Carlos','Luís','Francisco','António','Manuel','Paulo'],
    fNomes:['Maria','Ana','Sofia','Inês','Beatriz','Catarina','Marta','Joana','Rita','Sara','Filipa','Carolina','Mariana','Teresa','Francisca'],
    sobs:['Silva','Santos','Ferreira','Pereira','Oliveira','Costa','Rodrigues','Martins','Jesus','Sousa','Fernandes','Gonçalves','Carvalho','Lopes','Marques'],
    cidades:['Lisboa','Porto','Braga','Coimbra','Faro','Setúbal','Funchal','Aveiro','Évora','Viseu'],
    estados:['Lisboa','Porto','Braga','Setúbal','Faro','Coimbra'],
    zip:'NNNN-NNN',ruas:['Rua Augusta','Avenida da Liberdade','Rua do Ouro','Rua Garrett']},
  AR:{nome:'Argentina',        bandeira:'🇦🇷',moeda:'ARS ($)',   doc:'DNI',fone:'+54 XX XXXX-XXXX',
    mNomes:['Mateo','Santiago','Lautaro','Thiago','Nicolás','Agustín','Facundo','Tomás','Bruno','Joaquín','Ignacio','Lucas','Marcos','Franco','Leandro'],
    fNomes:['Valentina','Martina','Lucía','Florencia','Camila','Agustina','Carolina','Rocío','Natalia','Florencia','Romina','Micaela','Julieta','Nadia','Sofía'],
    sobs:['González','Rodríguez','Gómez','Fernández','López','Díaz','Martínez','Pérez','García','Sánchez','Romero','Sosa','Torres','Álvarez','Ruiz'],
    cidades:['Buenos Aires','Córdoba','Rosario','Mendoza','La Plata','Tucumán','Mar del Plata','Salta','Santa Fe','San Juan'],
    estados:['Buenos Aires','Córdoba','Santa Fe','Mendoza','Tucumán'],
    zip:'ANNNNAAA',ruas:['Av. Corrientes','Calle Florida','Av. 9 de Julio','Av. Santa Fe']},
  MX:{nome:'México',           bandeira:'🇲🇽',moeda:'MXN ($)',   doc:'CURP',fone:'+52 XXX XXX XXXX',
    mNomes:['José','Juan','Carlos','Miguel','Luis','Eduardo','Fernando','Alejandro','Ricardo','Jorge','Pablo','Arturo','Rodrigo','Manuel','Diego'],
    fNomes:['María','Guadalupe','Mariana','Sofía','Daniela','Fernanda','Valeria','Alejandra','Ana','Paulina','Karla','Adriana','Carmen','Rosa','Claudia'],
    sobs:['García','Hernández','Martínez','López','González','Pérez','Sánchez','Ramírez','Torres','Flores','Cruz','Reyes','Morales','Jiménez','Ruiz'],
    cidades:['Ciudad de México','Guadalajara','Monterrey','Puebla','Tijuana','León','Juárez','Zapopan','Mérida','Cancún'],
    estados:['CDMX','Jalisco','Nuevo León','Puebla','BC','Veracruz','Guanajuato','Chihuahua'],
    zip:'NNNNN',ruas:['Av. Insurgentes','Paseo de la Reforma','Av. Juárez','Calle Hidalgo']},
  JP:{nome:'Japão',            bandeira:'🇯🇵',moeda:'JPY (¥)',   doc:'Mainhon Residence Card',fone:'+81 XX XXXX XXXX',
    mNomes:['Haruto','Yuto','Sota','Yuki','Hayato','Haruki','Riku','Daiki','Shota','Kento','Ryota','Takumi','Kaito','Sho','Ren'],
    fNomes:['Hina','Yui','Yuina','Saki','Yuna','Riko','Miyu','Aoi','Rin','Miku','Sakura','Nana','Misaki','Ayane','Haruna'],
    sobs:['Sato','Suzuki','Tanaka','Watanabe','Ito','Yamamoto','Nakamura','Kobayashi','Kato','Yoshida','Yamada','Sasaki','Yamaguchi','Saito','Matsumoto'],
    cidades:['Tokyo','Osaka','Yokohama','Nagoya','Sapporo','Fukuoka','Kobe','Kawasaki','Kyoto','Saitama'],
    estados:['Tokyo','Osaka','Kanagawa','Aichi','Hokkaido','Fukuoka'],
    zip:'NNN-NNNN',ruas:['Shinjuku','Shibuya','Ginza','Akihabara','Asakusa']},
  CN:{nome:'China',            bandeira:'🇨🇳',moeda:'CNY (¥)',   doc:'Resident ID',fone:'+86 XXX XXXX XXXX',
    mNomes:['Wei','Fang','Lei','Jian','Tao','Hao','Yang','Chao','Qiang','Bin','Jie','Ming','Peng','Bo','Hui'],
    fNomes:['Fang','Min','Xia','Juan','Li','Na','Wei','Ling','Jing','Ying','Xiu','Hong','Yan','Mei','Ping'],
    sobs:['Wang','Li','Zhang','Liu','Chen','Yang','Huang','Zhao','Wu','Zhou','Xu','Sun','Ma','Zhu','Hu'],
    cidades:['Beijing','Shanghai','Guangzhou','Shenzhen','Chengdu','Chongqing','Wuhan','Xi\'an','Hangzhou','Nanjing'],
    estados:['Beijing','Shanghai','Guangdong','Zhejiang','Sichuan','Chongqing','Hubei'],
    zip:'NNNNNN',ruas:['Nanjing Road','Wangfujing','People\'s Square','Jiefang Road']},
  RU:{nome:'Rússia',           bandeira:'🇷🇺',moeda:'RUB (₽)',   doc:'Passeport Interne',fone:'+7 XXX XXX-XX-XX',
    mNomes:['Alexander','Dmitry','Maxim','Sergei','Andrei','Ivan','Mikhail','Nikita','Artem','Pavel','Kirill','Viktor','Roman','Alexei','Vladimir'],
    fNomes:['Anna','Maria','Elena','Natalia','Olga','Tatiana','Irina','Ekaterina','Julia','Svetlana','Anastasia','Oksana','Inna','Vera','Lyudmila'],
    sobs:['Ivanov','Smirnov','Kuznetsov','Popov','Vasiliev','Petrov','Sokolov','Mikhailov','Novikov','Fedorov','Morozov','Volkov','Alekseev','Lebedev','Semyonov'],
    cidades:['Moscow','Saint Petersburg','Novosibirsk','Yekaterinburg','Kazan','Nizhny Novgorod','Chelyabinsk','Samara','Omsk','Rostov-on-Don'],
    estados:['Moscow','Saint Petersburg','Novosibirsk','Sverdlovsk','Tatarstan'],
    zip:'NNNNNN',ruas:['Tverskaya','Arbat','Nevsky Prospekt','Lenina']},
  IN:{nome:'Índia',            bandeira:'🇮🇳',moeda:'INR (₹)',   doc:'Aadhaar',fone:'+91 XXXXX XXXXX',
    mNomes:['Aarav','Vihaan','Arjun','Reyansh','Aayan','Dhruv','Atharv','Sai','Krishna','Rohan','Rahul','Amit','Raj','Ankit','Vikram'],
    fNomes:['Saanvi','Aanya','Ananya','Pari','Navya','Ishita','Priya','Riya','Kavya','Pooja','Neha','Sneha','Divya','Meera','Anjali'],
    sobs:['Sharma','Verma','Singh','Patel','Gupta','Kumar','Mehta','Jain','Shah','Yadav','Nair','Reddy','Pillai','Iyer','Mishra'],
    cidades:['Mumbai','Delhi','Bangalore','Hyderabad','Chennai','Kolkata','Pune','Ahmedabad','Jaipur','Surat'],
    estados:['Maharashtra','Delhi','Karnataka','Telangana','Tamil Nadu','West Bengal','Rajasthan','Gujarat'],
    zip:'NNNNNN',ruas:['MG Road','Park Street','Brigade Road','Linking Road']},
  AU:{nome:'Austrália',        bandeira:'🇦🇺',moeda:'AUD ($)',   doc:'Driver\'s Licence',fone:'+61 X XXXX XXXX',
    mNomes:['Oliver','William','Jack','Noah','Thomas','James','Henry','Ethan','Lucas','Mason','Liam','Harrison','Lachlan','Cooper','Max'],
    fNomes:['Charlotte','Olivia','Amelia','Ava','Mia','Isla','Grace','Harper','Ella','Chloe','Zoe','Sophie','Lily','Hannah','Emily'],
    sobs:['Smith','Jones','Williams','Brown','Wilson','Taylor','Johnson','White','Martin','Anderson','Thompson','Davis','Robinson','Clark','Lewis'],
    cidades:['Sydney','Melbourne','Brisbane','Perth','Adelaide','Gold Coast','Canberra','Newcastle','Hobart','Darwin'],
    estados:['NSW','VIC','QLD','WA','SA','ACT','TAS','NT'],
    zip:'NNNN',ruas:['George Street','Collins Street','Queen Street','Bourke Street']},
  CA:{nome:'Canadá',           bandeira:'🇨🇦',moeda:'CAD ($)',   doc:'Health Card',fone:'+1 (XXX) XXX-XXXX',
    mNomes:['Liam','Noah','Oliver','William','James','Benjamin','Lucas','Henry','Alexander','Mason','Ethan','Logan','Elijah','Aiden','Jackson'],
    fNomes:['Emma','Olivia','Ava','Sophia','Isabella','Charlotte','Amelia','Mia','Harper','Evelyn','Abigail','Emily','Ella','Elizabeth','Sofia'],
    sobs:['Smith','Johnson','Williams','Brown','Jones','Miller','Davis','Wilson','Moore','Taylor','Anderson','Thomas','Jackson','White','Harris'],
    cidades:['Toronto','Vancouver','Montreal','Calgary','Ottawa','Edmonton','Winnipeg','Quebec City','Hamilton','Kitchener'],
    estados:['ON','BC','QC','AB','MB','SK','NS'],
    zip:'ANA NAN',ruas:['Main Street','King Street','Queen Street','Yonge Street']},
  NL:{nome:'Holanda',          bandeira:'🇳🇱',moeda:'EUR (€)',   doc:'Paspoort',fone:'+31 X XX XX XX XX',
    mNomes:['Liam','Lucas','Noah','Daan','Sem','Finn','Milan','Lars','Tim','Bram','Jesse','Tom','Bas','Cas','Robin'],
    fNomes:['Emma','Olivia','Mia','Tess','Sophie','Lotte','Sara','Julia','Femke','Noa','Lisa','Fleur','Roos','Eva','Lies'],
    sobs:['de Jong','Janssen','de Vries','van den Berg','van Dijk','Bakker','Visser','Smit','Meijer','de Boer','Mulder','de Graaf','Bos','Hendriks'],
    cidades:['Amsterdam','Rotterdam','Den Haag','Utrecht','Eindhoven','Groningen','Tilburg','Almere','Breda','Nijmegen'],
    estados:['Noord-Holland','Zuid-Holland','Utrecht','Noord-Brabant','Gelderland'],
    zip:'NNNN AA',ruas:['Kalverstraat','Damrak','Lijnbaansgracht','Herengracht']},
  SE:{nome:'Suécia',           bandeira:'🇸🇪',moeda:'SEK (kr)',  doc:'Personnummer',fone:'+46 XX XXX XX XX',
    mNomes:['Lucas','William','Oscar','Liam','Elias','Alexander','Hugo','Oliver','Viktor','Filip','Emil','Axel','Erik','Anton','Adam'],
    fNomes:['Maja','Alice','Elsa','Saga','Linnea','Olivia','Emma','Astrid','Vera','Ebba','Julia','Wilma','Stella','Lova','Hanna'],
    sobs:['Johansson','Andersson','Karlsson','Nilsson','Eriksson','Larsson','Olsson','Persson','Svensson','Gustafsson','Pettersson','Jonsson','Lindström','Lindberg'],
    cidades:['Stockholm','Göteborg','Malmö','Uppsala','Västerås','Örebro','Linköping','Helsingborg','Jönköping','Norrköping'],
    estados:['Stockholm','Västra Götaland','Skåne','Östergötland','Uppsala'],
    zip:'NNN NN',ruas:['Kungsgatan','Drottninggatan','Storgatan','Birger Jarlsgatan']},
  PL:{nome:'Polônia',          bandeira:'🇵🇱',moeda:'PLN (zł)',  doc:'Dowód Osobisty',fone:'+48 XXX XXX XXX',
    mNomes:['Jakub','Michał','Bartosz','Mateusz','Piotr','Marcin','Paweł','Tomasz','Łukasz','Kamil','Szymon','Krzysztof','Rafał','Marek','Grzegorz'],
    fNomes:['Anna','Maria','Katarzyna','Małgorzata','Agnieszka','Joanna','Barbara','Karolina','Natalia','Paulina','Monika','Zofia','Wiktoria','Julia','Aleksandra'],
    sobs:['Kowalski','Nowak','Wiśniewski','Wójcik','Kowalczyk','Kamiński','Lewandowski','Zieliński','Woźniak','Szymański','Dąbrowski','Kozłowski','Jankowski','Mazur'],
    cidades:['Warszawa','Kraków','Łódź','Wrocław','Poznań','Gdańsk','Szczecin','Bydgoszcz','Lublin','Katowice'],
    estados:['Masowieckie','Małopolskie','Łódź','Dolnośląskie','Wielkopolskie'],
    zip:'NN-NNN',ruas:['Ulica Marszałkowska','Krakowskie Przedmieście','Nowy Świat','Aleje Jerozolimskie']},
  TR:{nome:'Turquia',          bandeira:'🇹🇷',moeda:'TRY (₺)',  doc:'Kimlik Kartı',fone:'+90 XXX XXX XXXX',
    mNomes:['Ahmet','Mehmet','Ali','Mustafa','Hüseyin','Hasan','İbrahim','İsmail','Ömer','Yusuf','Murat','Emre','Burak','Can','Kerem'],
    fNomes:['Fatma','Ayşe','Emine','Hatice','Zeynep','Elif','Meryem','Zehra','Esra','Büşra','Merve','Seda','Gül','Nur','Hilal'],
    sobs:['Yılmaz','Kaya','Demir','Çelik','Şahin','Yıldız','Yıldırım','Öztürk','Aydın','Arslan','Doğan','Kılıç','Aslan','Çetin','Koç'],
    cidades:['İstanbul','Ankara','İzmir','Bursa','Antalya','Adana','Konya','Gaziantep','Kocaeli','Mersin'],
    estados:['İstanbul','Ankara','İzmir','Bursa','Antalya'],
    zip:'NNNNN',ruas:['İstiklal Caddesi','Bağdat Caddesi','Atatürk Bulvarı','Konyaaltı Caddesi']},
};
const _PAIS_IDS = Object.keys(_PAISES);

const _GENEROS = ['M','F','M','F','M','F','NB','TM','TF']; // weighted
const _GENERO_LABEL = {M:'Masculino',F:'Feminino',NB:'Não-binário',TM:'Trans Masculino',TF:'Trans Feminino'};

const _RACAS = [
  {id:'branco',     pt:'Branco/Caucasiano',    en:'White/Caucasian'},
  {id:'negro',      pt:'Negro/Afrodescendente',en:'Black/African'},
  {id:'pardo',      pt:'Pardo/Mestiço',        en:'Mixed/Biracial'},
  {id:'asiatico',   pt:'Asiático',             en:'Asian'},
  {id:'indigena',   pt:'Indígena',             en:'Indigenous'},
  {id:'hispânico',  pt:'Hispânico',            en:'Hispanic/Latino'},
  {id:'árabe',      pt:'Árabe/Médio-Oriental', en:'Arab/Middle Eastern'},
  {id:'sulasiatico',pt:'Sul-Asiático',         en:'South Asian'},
];

const _OLHOS = {
  branco:['Azul','Verde','Avelã','Cinza','Castanho claro'],
  negro:['Castanho escuro','Preto','Castanho'],
  pardo:['Castanho','Avelã','Verde','Castanho escuro'],
  asiatico:['Castanho escuro','Preto','Castanho'],
  indigena:['Castanho escuro','Preto'],
  hispânico:['Castanho','Castanho escuro','Avelã'],
  árabe:['Castanho escuro','Preto','Castanho','Verde'],
  sulasiatico:['Castanho escuro','Preto','Castanho'],
};
const _PELE = {
  branco:['Muito clara (I)','Clara (II)','Bege claro (III)'],
  negro:['Marrom escuro (V)','Muito escura (VI)','Marrom médio (IV)'],
  pardo:['Bege médio (III)','Marrom claro (IV)','Clara (II)'],
  asiatico:['Amarela clara (II)','Bege médio (III)','Olivácea (IV)'],
  indigena:['Olivácea (IV)','Bronzeada (III)','Marrom claro (IV)'],
  hispânico:['Olivácea (IV)','Clara (II)','Bronzeada (III)'],
  árabe:['Olivácea (IV)','Bege médio (III)','Bronzeada (III)'],
  sulasiatico:['Morena clara (III)','Olivácea (IV)','Marrom médio (V)'],
};
const _CABELO_COR = {
  branco:['Loiro','Loiro escuro','Castanho claro','Ruivo','Castanho','Preto'],
  negro:['Preto','Castanho muito escuro'],
  pardo:['Castanho escuro','Preto','Castanho','Castanho claro'],
  asiatico:['Preto','Castanho muito escuro'],
  indigena:['Preto'],
  hispânico:['Preto','Castanho escuro','Castanho'],
  árabe:['Preto','Castanho escuro'],
  sulasiatico:['Preto','Castanho muito escuro'],
};
const _CABELO_TIPO = ['Liso','Liso fino','Ondulado','Cacheado','Crespo'];
const _TIPO_SANGUINEO = ['A+','A-','B+','B-','AB+','AB-','O+','O-'];
const _MBTI = ['INTJ','INTP','ENTJ','ENTP','INFJ','INFP','ENFJ','ENFP','ISTJ','ISFJ','ESTJ','ESFJ','ISTP','ISFP','ESTP','ESFP'];
const _MBTI_DESC = {INTJ:'Arquiteto',INTP:'Lógico',ENTJ:'Comandante',ENTP:'Inovador',INFJ:'Advogado',INFP:'Mediador',ENFJ:'Protagonista',ENFP:'Ativista',ISTJ:'Logístico',ISFJ:'Defensor',ESTJ:'Executivo',ESFJ:'Cônsul',ISTP:'Virtuoso',ISFP:'Aventureiro',ESTP:'Empreendedor',ESFP:'Animador'};
const _SIGNOS = [{n:'Áries',d:'21/03-19/04'},{n:'Touro',d:'20/04-20/05'},{n:'Gêmeos',d:'21/05-20/06'},{n:'Câncer',d:'21/06-22/07'},{n:'Leão',d:'23/07-22/08'},{n:'Virgem',d:'23/08-22/09'},{n:'Libra',d:'23/09-22/10'},{n:'Escorpião',d:'23/10-21/11'},{n:'Sagitário',d:'22/11-21/12'},{n:'Capricórnio',d:'22/12-19/01'},{n:'Aquário',d:'20/01-18/02'},{n:'Peixes',d:'19/02-20/03'}];
const _LANG_AMOR = ['Palavras de afirmação','Tempo de qualidade','Presentes','Atos de serviço','Toque físico'];
const _ESTILOS_APRENDIZADO = ['Visual','Auditivo','Cinestésico','Leitura/Escrita'];
const _MUSICA = ['Pop','Rock','Sertanejo','Forró','Samba','MPB','Funk','Pagode','Hip-Hop','Eletrônica','Jazz','Blues','Clássica','Metal','R&B','Gospel','Reggae','K-Pop','Indie','Country'];
const _COMIDA = ['Italiana','Brasileira','Japonesa','Mexicana','Chinesa','Árabe','Fast Food','Mediterrânea','Indiana','Francesa','Churrasco','Vegana/Vegetariana','Frutos do Mar','Tailandesa','Peruana'];
const _ESPORTES = ['Futebol','Vôlei','Basquete','Tênis','Natação','Corrida','Ciclismo','Musculação','Artes Marciais','Yoga','Crossfit','Futebol americano','Baseball','Golfe','Escalada','Surfe','Skate','Handball'];
const _HOBBIES = ['Ler','Cozinhar','Gaming','Fotografia','Viajar','Pintura','Música','Cinema','Jardinagem','Tricô/Crochê','Desenho','Escrever','Camping','Programação','Culinária','Dança','Teatro','Podcast','Yoga','Meditação','Colecionismo','DIY','Pesca','Aquarismo','Pet care','Voluntariado','Idiomas','Astronomia','Curadoria de arte','Caça ao tesouro'];
const _FILMES = ['Ação','Comédia','Drama','Terror','Suspense','Ficção Científica','Animação','Romance','Documentário','Fantasia','Aventura','Crime','Faroeste','Musical','Biográfico'];
const _LIVROS = ['Romance','Ficção científica','Fantasia','Terror','Policial','Autoajuda','Biografia','História','Filosofia','Negócios','Aventura','Distopia','Psicológico','Drama literário','HQ/Mangá'];
const _STREAMING = ['Netflix','Prime Video','Disney+','HBO Max','Apple TV+','Globoplay','Spotify','Deezer','YouTube','Crunchyroll','Paramount+'];
const _REDES = ['Instagram','TikTok','Twitter/X','Facebook','LinkedIn','YouTube','Pinterest','Reddit','WhatsApp','Telegram','Discord','Snapchat'];
const _PETS = ['Nenhum','Cachorro','Gato','Cachorro e Gato','Pássaro','Peixe','Coelho','Hamster','Réptil'];
const _RELIGIAO = ['Católico','Evangélico','Espírita','Ateu','Agnóstico','Budista','Muçulmano','Judaico','Umbanda/Candomblé','Hindu','Sem religião','Cristão (outros)'];
const _POLITICA = ['Progressista','Conservador','Liberal','Moderado','Libertário','Sem preferência','Apolítico'];
const _ESCOLARIDADE = ['Fundamental incompleto','Fundamental completo','Médio incompleto','Médio completo','Superior incompleto','Superior completo','Pós-graduação','Mestrado','Doutorado'];
const _ESTADO_CIVIL = ['Solteiro(a)','Casado(a)','Divorciado(a)','Viúvo(a)','União estável','Namorando','Separado(a)'];
const _OCUPACOES = ['Engenheiro(a) de Software','Médico(a)','Professor(a)','Advogado(a)','Administrador(a)','Enfermeiro(a)','Arquiteto(a)','Psicólogo(a)','Designer','Jornalista','Contador(a)','Vendedor(a)','Motorista','Mecânico(a)','Chef de Cozinha','Analista de TI','Gerente Comercial','Técnico(a) de Informática','Eletricista','Dentista','Fisioterapeuta','Nutricionista','Marketing Digital','Desenvolvedor(a) Web','DevOps Engineer','Cientista de Dados'];
const _RENDA = ['Menos de R$1.500','R$1.500–R$3.000','R$3.000–R$6.000','R$6.000–R$10.000','R$10.000–R$20.000','Acima de R$20.000'];
const _AREAS = ['Tecnologia','Saúde','Educação','Direito','Engenharia','Comércio','Finanças','Comunicação','Arte e Cultura','Construção Civil','Logística','Recursos Humanos','Marketing','Ciências','Serviços Públicos'];
const _CORES_FAV = ['Azul','Verde','Vermelho','Preto','Branco','Roxo','Rosa','Laranja','Amarelo','Cinza','Turquesa','Lilás','Dourado','Prata','Bege','Marinho','Bordô','Coral','Teal','Índigo'];
const _ESTILOS_VIDA = ['Fitness','Minimalista','Gourmet','Tech','Outdoor','Urbano','Casual','Sustentável','Workaholic','Nômade digital','Homebody','Social'];
const _FRUTAS_FAV = ['Manga','Morango','Melancia','Uva','Maçã','Banana','Laranja','Abacaxi','Pêssego','Framboesa','Limão','Maracujá'];
const _ESTACOES = ['Verão','Outono','Inverno','Primavera'];
const _HORA_DIA = ['Matutino (madrugador)','Vespertino','Noturno (coruja)'];
const _INTOLERANCIAS = ['Nenhuma','Lactose','Glúten','Amendoim','Frutos do mar','Ovos','Soja'];
const _VIAGEM = ['Praia','Montanha','Cidade grande','Interior/Rural','Ecoturismo','Culturais/Históricos','Parques temáticos','Cruzeiro','Aventura'];

// ─── IP e User Agent fictícios ────────────────────────────────────────
function _genIP(){return`${_rnd(1,254)}.${_rnd(0,255)}.${_rnd(0,255)}.${_rnd(1,254)}`;}
const _UAS=['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36','Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15','Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148','Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36'];

// ─── Email ────────────────────────────────────────────────────────────
const _DOMAINS=['gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','protonmail.com'];
function _nomeToEmail(nome){
  const p=nome.normalize('NFD').replace(/[̀-ͯ]/g,'').toLowerCase().replace(/[^a-z0-9\s]/g,'').split(/\s+/);
  const u=p[0]+(Math.random()>.5?'.'+p[p.length-1]:String(_rnd(1,999)));
  return`${u}@${_pick(_DOMAINS)}`;
}
function _genPhone(pais){
  const fmt=(_PAISES[pais]||_PAISES.BR).fone;
  return fmt.replace(/X/g,()=>_rnd(0,9)).replace(/N/g,()=>_rnd(1,9));
}

// ─── Gerador de Pessoa Completa ───────────────────────────────────────
function _genPessoaCompleta(paisId='BR', generoId=null, racaId=null){
  const pais = _PAISES[paisId] || _PAISES.BR;
  const g = generoId==='R' ? _pick(_GENEROS) : (generoId || _pick(_GENEROS));
  const r = racaId==='R' ? _pick(_RACAS) : (_RACAS.find(x=>x.id===racaId) || _pick(_RACAS));
  const isMale = g==='M'||g==='TM';
  const fn = _pick(isMale?pais.mNomes:pais.fNomes);
  const ln = _pick(pais.sobs);
  const ln2 = _pick(pais.sobs);
  const nomeCompleto = `${fn} ${ln} ${ln2}`;
  const byY = _rnd(1955,2006), byM=_pad(_rnd(1,12),2), byD=_pad(_rnd(1,28),2);
  const idade = new Date().getFullYear()-byY;
  const signo = _pick(_SIGNOS);
  const mbti = _pick(_MBTI);
  const cidade = _pick(pais.cidades);
  const estado = _pick(pais.estados);
  const rua = _pick(pais.ruas||['Main Street']);
  const num = _rnd(1,9999);
  const zip = pais.zip.replace(/N/g,()=>_rnd(0,9)).replace(/A/g,()=>_LS[_rnd(0,25)]);
  const hobbiesQty = _rnd(3,5);
  const hobbies = [..._HOBBIES].sort(()=>Math.random()-.5).slice(0,hobbiesQty);
  const musicas = [..._MUSICA].sort(()=>Math.random()-.5).slice(0,_rnd(2,4));
  const streaming = [..._STREAMING].sort(()=>Math.random()-.5).slice(0,_rnd(2,4));
  const olhos = _pick((_OLHOS[r.id]||_OLHOS.pardo));
  const pele = _pick((_PELE[r.id]||_PELE.pardo));
  const cabCor = _pick((_CABELO_COR[r.id]||_CABELO_COR.pardo));
  const cabTipo = _pick(_CABELO_TIPO);
  const altBase = isMale?_rnd(163,191):_rnd(152,178);
  const altCm = altBase;
  const pesoKg = Math.round(altCm*0.38+_rnd(-8,12));
  const docs = paisId==='BR'
    ? {CPF:_genCPF(true),RG:_genRG(true),CNH:_genCNH(),PIS:_genPIS(true),'Título de Eleitor':_genTitulo(true)}
    : {[pais.doc]: _pad(_rnd(100000000,999999999),9)};
  return {
    // Identificação
    nome_completo: nomeCompleto, primeiro_nome: fn, sobrenome: `${ln} ${ln2}`,
    genero: _GENERO_LABEL[g]||g, raca: r.pt, pais: `${pais.bandeira} ${pais.nome}`,
    naturalidade: `${cidade}, ${estado}`,
    nascimento: `${byD}/${byM}/${byY}`, idade: `${idade} anos`,
    signo: `${signo.n} (${signo.d})`, tipo_sanguineo: _pick(_TIPO_SANGUINEO),
    estado_civil: _pick(_ESTADO_CIVIL), filhos: _rnd(0,4),
    // Contato
    email_principal: _nomeToEmail(nomeCompleto),
    email_alternativo: _nomeToEmail(fn+ln),
    telefone: _genPhone(paisId), telefone_2: _genPhone(paisId),
    // Endereço
    endereco: `${rua}, ${num}`, cidade, estado, cep: zip, pais_nome: pais.nome,
    // Documentos
    documentos: docs,
    // Físico
    altura: `${altCm} cm (${Math.floor(altCm/30.48)}′${Math.round((altCm/2.54)%12)}″)`,
    peso: `${pesoKg} kg (${Math.round(pesoKg*2.205)} lbs)`,
    cor_olhos: olhos, tom_pele: pele, cor_cabelo: cabCor, tipo_cabelo: cabTipo,
    // Personalidade
    mbti: `${mbti} — ${_MBTI_DESC[mbti]}`, linguagem_amor: _pick(_LANG_AMOR),
    estilo_aprendizado: _pick(_ESTILOS_APRENDIZADO),
    // Profissional
    ocupacao: _pick(_OCUPACOES), area: _pick(_AREAS), escolaridade: _pick(_ESCOLARIDADE),
    renda: _pick(_RENDA), empresa: `${_pick(['Tech','Nova','Prime','Alpha','Global'])} ${_pick(['Solutions','Systems','Corp','Group','Inc'])}`,
    // Preferências
    cor_favorita: _pick(_CORES_FAV), estacao_favorita: _pick(_ESTACOES), hora_preferida: _pick(_HORA_DIA),
    comida: _pick(_COMIDA), fruta_favorita: _pick(_FRUTAS_FAV), intolerancias: _pick(_INTOLERANCIAS),
    esporte: _pick(_ESPORTES), hobbies, musica: musicas, filme: _pick(_FILMES), livro: _pick(_LIVROS),
    streaming, rede_social: _pick(_REDES), pet: _pick(_PETS), estilo_vida: _pick(_ESTILOS_VIDA),
    viagem: _pick(_VIAGEM),
    // Crenças
    religiao: _pick(_RELIGIAO), politica: _pick(_POLITICA),
    // Digital
    username: fn.toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g,'')+_rnd(10,9999),
    senha: _genSenha(14,true,true,true,true),
    ip: _genIP(), user_agent: _pick(_UAS), moeda: pais.moeda,
  };
}

// ════════════════════════════════════════════════════════════════════════
//  BULK UI HELPER
// ════════════════════════════════════════════════════════════════════════

window._genBulkResults = [];
function _bulkCopyAll(){ _copyToClipboard(window._genBulkResults.join('\n')); _genFlash('bulk-copy-all','✓ Copiado!','📋 Copiar Tudo'); }
function _bulkDownload(name){
  const blob=new Blob([window._genBulkResults.join('\n')],{type:'text/plain'});
  const a=document.createElement('a'); a.href=URL.createObjectURL(blob);
  a.download=`${name}_${Date.now()}.txt`; a.click();
}
function _genFlash(btnId, msg, restore){
  const el=document.getElementById(btnId);
  if(!el)return; el.textContent=msg; setTimeout(()=>el.textContent=restore,1500);
}

function _bulkControls(genId, hasMask=true, extra=''){
  return `
    <div class="gen-card">
      <div class="gen-bulk-row">
        <div class="gen-field-group"><label>Quantidade</label><input type="number" id="${genId}-qty" value="1" min="1" max="1000" class="gen-input" style="width:90px"></div>
        ${hasMask?`<div class="gen-field-group"><label>Formato</label><select id="${genId}-mask" class="gen-input"><option value="1">Com pontuação</option><option value="0">Sem pontuação</option></select></div>`:''}
        ${extra}
      </div>
      <div class="gen-bulk-actions" style="margin-top:12px">
        <button class="btn btn-primary" onclick="genExec_${genId}()">↻ Gerar</button>
        <button class="btn btn-secondary" id="bulk-copy-all" onclick="_bulkCopyAll()">📋 Copiar Tudo</button>
        <button class="btn btn-secondary" onclick="_bulkDownload('${genId}')">⬇ .TXT</button>
      </div>
    </div>
    <div class="gen-card gen-bulk-output-card">
      <div class="gen-bulk-stats" id="${genId}-stats" style="display:none"></div>
      <div class="gen-bulk-list" id="${genId}-output"></div>
    </div>`;
}

function _renderBulkList(id, items){
  window._genBulkResults = items;
  const el = document.getElementById(`${id}-output`);
  const st = document.getElementById(`${id}-stats`);
  if(!el) return;
  if(st){ st.style.display=''; st.textContent=`${items.length} itens gerados`; }
  el.innerHTML = items.map((v,i)=>`
    <div class="gen-bulk-item">
      <span class="gen-bulk-num">${String(i+1).padStart(3,'0')}</span>
      <span class="gen-bulk-val">${_esc(v)}</span>
    </div>`).join('');
}

// ════════════════════════════════════════════════════════════════════════
//  RENDER FUNCTIONS — SIMPLE GENERATORS (bulk + mask)
// ════════════════════════════════════════════════════════════════════════

function _genRender_cpf(){return`
  <div class="gen-top-bar"><h2>🪪 Gerador de CPF</h2></div>
  ${_bulkControls('cpf',true)}
  <div class="gen-info-box">Gerado com algoritmo oficial de dois dígitos verificadores.</div>`;
}
window.genExec_cpf = function(){
  const q=parseInt(document.getElementById('cpf-qty')?.value||1),m=document.getElementById('cpf-mask')?.value==='1';
  _renderBulkList('cpf', Array.from({length:q},()=>_genCPF(m)));
};

function _genRender_cnpj(){return`
  <div class="gen-top-bar"><h2>🏢 Gerador de CNPJ</h2></div>
  ${_bulkControls('cnpj',true)}
  <div class="gen-info-box">CNPJ com algoritmo oficial de dígitos verificadores.</div>`;
}
window.genExec_cnpj = function(){
  const q=parseInt(document.getElementById('cnpj-qty')?.value||1),m=document.getElementById('cnpj-mask')?.value==='1';
  _renderBulkList('cnpj', Array.from({length:q},()=>_genCNPJ(m)));
};

function _genRender_rg(){return`
  <div class="gen-top-bar"><h2>📄 Gerador de RG</h2></div>
  ${_bulkControls('rg',true)}
  <div class="gen-info-box">Formato SP: XX.XXX.XXX-D (D pode ser dígito ou X).</div>`;
}
window.genExec_rg = function(){
  const q=parseInt(document.getElementById('rg-qty')?.value||1),m=document.getElementById('rg-mask')?.value==='1';
  _renderBulkList('rg', Array.from({length:q},()=>_genRG(m)));
};

function _genRender_cep(){return`
  <div class="gen-top-bar"><h2>📮 Gerador de CEP</h2></div>
  ${_bulkControls('cep',true)}`;
}
window.genExec_cep = function(){
  const q=parseInt(document.getElementById('cep-qty')?.value||1),m=document.getElementById('cep-mask')?.value==='1';
  _renderBulkList('cep', Array.from({length:q},()=>_genCEP(m)));
};

function _genRender_pis(){return`
  <div class="gen-top-bar"><h2>💼 Gerador de PIS/PASEP</h2></div>
  ${_bulkControls('pis',true)}
  <div class="gen-info-box">11 dígitos com dígito verificador (mod 11).</div>`;
}
window.genExec_pis = function(){
  const q=parseInt(document.getElementById('pis-qty')?.value||1),m=document.getElementById('pis-mask')?.value==='1';
  _renderBulkList('pis', Array.from({length:q},()=>_genPIS(m)));
};

function _genRender_renavam(){return`
  <div class="gen-top-bar"><h2>🚗 Gerador de RENAVAM</h2></div>
  ${_bulkControls('renavam',true)}`;
}
window.genExec_renavam = function(){
  const q=parseInt(document.getElementById('renavam-qty')?.value||1),m=document.getElementById('renavam-mask')?.value==='1';
  _renderBulkList('renavam', Array.from({length:q},()=>_genRENAVAM(m)));
};

function _genRender_cnh(){return`
  <div class="gen-top-bar"><h2>🪪 Gerador de CNH</h2></div>
  ${_bulkControls('cnh',false)}
  <div class="gen-info-box">11 dígitos com dois dígitos verificadores.</div>`;
}
window.genExec_cnh = function(){
  const q=parseInt(document.getElementById('cnh-qty')?.value||1);
  _renderBulkList('cnh', Array.from({length:q},()=>_genCNH()));
};

function _genRender_titulo(){return`
  <div class="gen-top-bar"><h2>🗳️ Gerador de Título de Eleitor</h2></div>
  ${_bulkControls('titulo',true)}`;
}
window.genExec_titulo = function(){
  const q=parseInt(document.getElementById('titulo-qty')?.value||1),m=document.getElementById('titulo-mask')?.value==='1';
  _renderBulkList('titulo', Array.from({length:q},()=>_genTitulo(m)));
};

function _genRender_ie(){
  const ufOpts=_IE_STATES.map(u=>`<option value="${u}">${u}</option>`).join('');
  return`
  <div class="gen-top-bar"><h2>🏪 Gerador de Inscrição Estadual</h2></div>
  ${_bulkControls('ie',true,`<div class="gen-field-group"><label>Estado</label><select id="ie-uf" class="gen-input"><option value="R">Aleatório</option>${ufOpts}</select></div>`)}`;
}
window.genExec_ie = function(){
  const q=parseInt(document.getElementById('ie-qty')?.value||1),m=document.getElementById('ie-mask')?.value==='1';
  const uf=document.getElementById('ie-uf')?.value;
  _renderBulkList('ie', Array.from({length:q},()=>{ const u=uf==='R'?_pick(_IE_STATES):uf; return _genIE(u,m).replace('/000',''); }));
};

function _genRender_cartao(){return`
  <div class="gen-top-bar"><h2>💳 Gerador de Cartão de Crédito</h2></div>
  ${_bulkControls('cartao',true,`<div class="gen-field-group"><label>Bandeira</label><select id="cartao-brand" class="gen-input"><option value="R">Aleatória</option>${_CARDS.map(c=>`<option value="${c.n}">${c.n}</option>`).join('')}</select></div>`)}
  <div class="gen-info-box">⚠️ Algoritmo Luhn. Números fictícios — não possuem fundos reais.</div>`;
}
window.genExec_cartao = function(){
  const q=parseInt(document.getElementById('cartao-qty')?.value||1),m=document.getElementById('cartao-mask')?.value==='1';
  const brand=document.getElementById('cartao-brand')?.value;
  _renderBulkList('cartao', Array.from({length:q},()=>{
    const saved=_CARDS.filter(c=>brand==='R'||c.n===brand);
    const b=_pick(saved.length?saved:_CARDS);
    const pfx=_pick(b.p).split('').map(Number);
    const n=[...pfx]; while(n.length<b.l-1)n.push(_rnd(0,9)); n.push(_luhn(n));
    const s=n.join('');
    const fmt=m?(b.l===15?s.replace(/(\d{4})(\d{6})(\d{5})/,'$1 $2 $3'):s.replace(/(\d{4})(\d{4})(\d{4})(\d{4})/,'$1 $2 $3 $4')):s;
    const mo=_pad(_rnd(1,12),2),yr=_rnd(new Date().getFullYear()+1,new Date().getFullYear()+5);
    const cvv=_pad(_rnd(0,b.l===15?9999:999),b.l===15?4:3);
    return`${b.n} | ${fmt} | ${mo}/${yr} | ${cvv}`;
  }));
};

function _genRender_placa(){return`
  <div class="gen-top-bar"><h2>🚘 Gerador de Placa de Veículos</h2></div>
  ${_bulkControls('placa',true,`<div class="gen-field-group"><label>Tipo</label><select id="placa-tipo" class="gen-input"><option value="R">Aleatório</option><option value="mercosul">Mercosul (ABC1D23)</option><option value="antiga">Antigo (ABC-1234)</option></select></div>`)}`;
}
window.genExec_placa = function(){
  const q=parseInt(document.getElementById('placa-qty')?.value||1),m=document.getElementById('placa-mask')?.value==='1';
  const t=document.getElementById('placa-tipo')?.value;
  _renderBulkList('placa', Array.from({length:q},()=>_genPlaca(t==='R'?null:t,m)));
};

function _genRender_veiculo(){return`
  <div class="gen-top-bar"><h2>🚙 Gerador de Veículos</h2></div>
  ${_bulkControls('veiculo',false)}`;
}
window.genExec_veiculo = function(){
  const q=parseInt(document.getElementById('veiculo-qty')?.value||1);
  _renderBulkList('veiculo', Array.from({length:q},()=>{ const v=_genVeiculo(); return`${v.marca} ${v.modelo} ${v.ano} | ${v.cor} | ${v.combustivel} | ${v.placa}`; }));
};

function _genRender_conta(){return`
  <div class="gen-top-bar"><h2>🏦 Gerador de Conta Bancária</h2></div>
  ${_bulkControls('conta',false)}
  <div class="gen-info-box">Dados fictícios — não representam contas reais.</div>`;
}
window.genExec_conta = function(){
  const q=parseInt(document.getElementById('conta-qty')?.value||1);
  _renderBulkList('conta', Array.from({length:q},()=>{ const c=_genConta(); return`${c.banco} | Ag: ${c.agencia} | Cc: ${c.conta} | ${c.tipo}`; }));
};

function _genRender_certidao(){return`
  <div class="gen-top-bar"><h2>📜 Gerador de Certidões</h2></div>
  ${_bulkControls('certidao',false,`<div class="gen-field-group"><label>Tipo</label><select id="cert-tipo" class="gen-input"><option value="R">Aleatório</option><option>Nascimento</option><option>Casamento</option><option>Óbito</option></select></div>`)}`;
}
window.genExec_certidao = function(){
  const q=parseInt(document.getElementById('certidao-qty')?.value||1);
  const t=document.getElementById('cert-tipo')?.value;
  _renderBulkList('certidao', Array.from({length:q},()=>{ const c=_genCertidao(); if(t&&t!=='R')c.tipo=t; return`[${c.tipo}] ${c.matricula} | ${c.cartorio} | ${c.uf} | ${c.data}`; }));
};

function _genRender_nome(){
  return`
  <div class="gen-top-bar"><h2>✍️ Gerador de Nomes</h2></div>
  ${_bulkControls('nome',false,`
    <div class="gen-field-group"><label>País</label><select id="nome-pais" class="gen-input"><option value="R">Aleatório</option>${_PAIS_IDS.map(p=>`<option value="${p}">${_PAISES[p].bandeira} ${_PAISES[p].nome}</option>`).join('')}</select></div>
    <div class="gen-field-group"><label>Gênero</label><select id="nome-genero" class="gen-input"><option value="R">Aleatório</option><option value="M">Masculino</option><option value="F">Feminino</option></select></div>`)}`;
}
window.genExec_nome = function(){
  const q=parseInt(document.getElementById('nome-qty')?.value||1);
  const p=document.getElementById('nome-pais')?.value;
  const g=document.getElementById('nome-genero')?.value;
  _renderBulkList('nome', Array.from({length:q},()=>{
    const pid=p==='R'?_pick(_PAIS_IDS):p;
    const pdata=_PAISES[pid]||_PAISES.BR;
    const gend=g==='R'?_pick(['M','F']):g;
    const fn=_pick(gend==='M'?pdata.mNomes:pdata.fNomes);
    const ln=_pick(pdata.sobs), ln2=_pick(pdata.sobs);
    return`${fn} ${ln} ${ln2} (${pdata.bandeira} ${pdata.nome})`;
  }));
};

function _genRender_nick(){return`
  <div class="gen-top-bar"><h2>🎮 Gerador de Nicks</h2></div>
  ${_bulkControls('nick',false)}`;
}
const _NICK_ADJ=['Dark','Shadow','Wolf','Fire','Iron','Storm','Cyber','Pixel','Neo','Ghost','Dead','Night','Steel','Blood','Crystal','Void','Toxic','Hyper','Ultra','Chaos'];
const _NICK_N=['Hacker','Hunter','Killer','Master','Rider','Knight','Dragon','Phoenix','Ninja','Warrior','Sniper','Ranger','Blade','Force','Strike','Coder','Zero','Root','Shell','Byte'];
window.genExec_nick = function(){
  const q=parseInt(document.getElementById('nick-qty')?.value||1);
  _renderBulkList('nick', Array.from({length:q},()=>{ const s=_pick(['','_','.','x','__']);const n=Math.random()>.4?String(_rnd(1,9999)):'';return _pick(_NICK_ADJ)+s+_pick(_NICK_N)+n; }));
};

function _genRender_senha(){return`
  <div class="gen-top-bar"><h2>🔑 Gerador de Senha</h2></div>
  <div class="gen-card">
    <div class="gen-bulk-row">
      <div class="gen-field-group"><label>Quantidade</label><input type="number" id="senha-qty" value="1" min="1" max="1000" class="gen-input" style="width:90px"></div>
      <div class="gen-field-group"><label>Comprimento</label><input type="number" id="pw-len" value="16" min="4" max="128" class="gen-input" style="width:90px"></div>
    </div>
    <div class="gen-pw-opts" style="margin-top:10px">
      <label><input type="checkbox" id="pw-lower" checked> a-z</label>
      <label><input type="checkbox" id="pw-upper" checked> A-Z</label>
      <label><input type="checkbox" id="pw-nums"  checked> 0-9</label>
      <label><input type="checkbox" id="pw-syms"  checked> !@#...</label>
    </div>
    <div class="gen-bulk-actions" style="margin-top:12px">
      <button class="btn btn-primary" onclick="genExec_senha()">↻ Gerar</button>
      <button class="btn btn-secondary" id="bulk-copy-all" onclick="_bulkCopyAll()">📋 Copiar Tudo</button>
      <button class="btn btn-secondary" onclick="_bulkDownload('senhas')">⬇ .TXT</button>
    </div>
  </div>
  <div class="gen-card gen-bulk-output-card"><div class="gen-bulk-stats" id="senha-stats" style="display:none"></div><div class="gen-bulk-list" id="senha-output"></div></div>`;
}
window.genExec_senha = function(){
  const q=parseInt(document.getElementById('senha-qty')?.value||1);
  const l=parseInt(document.getElementById('pw-len')?.value||16);
  const lo=document.getElementById('pw-lower')?.checked??true;
  const up=document.getElementById('pw-upper')?.checked??true;
  const nu=document.getElementById('pw-nums')?.checked??true;
  const sy=document.getElementById('pw-syms')?.checked??true;
  _renderBulkList('senha', Array.from({length:q},()=>_genSenha(l,lo,up,nu,sy)));
};


function _genRender_numeros(){return`
  <div class="gen-top-bar"><h2>🔢 Gerador de Números Aleatórios</h2></div>
  <div class="gen-card">
    <div class="gen-bulk-row">
      <div class="gen-field-group"><label>De</label><input type="number" id="num-min" value="1" class="gen-input" style="width:90px"></div>
      <div class="gen-field-group"><label>Até</label><input type="number" id="num-max" value="100" class="gen-input" style="width:90px"></div>
      <div class="gen-field-group"><label>Quantidade</label><input type="number" id="num-qty" value="10" min="1" max="1000" class="gen-input" style="width:90px"></div>
      <div class="gen-field-group" style="justify-content:flex-end;padding-top:18px"><label><input type="checkbox" id="num-unique"> Sem repetição</label></div>
    </div>
    <div class="gen-bulk-actions" style="margin-top:12px">
      <button class="btn btn-primary" onclick="genExec_numeros()">↻ Gerar</button>
      <button class="btn btn-secondary" id="bulk-copy-all" onclick="_bulkCopyAll()">📋 Copiar Tudo</button>
      <button class="btn btn-secondary" onclick="_bulkDownload('numeros')">⬇ .TXT</button>
    </div>
  </div>
  <div class="gen-card gen-bulk-output-card"><div class="gen-bulk-stats" id="numeros-stats" style="display:none"></div><div class="gen-bulk-list" id="numeros-output"></div></div>`;
}
window.genExec_numeros = function(){
  const mn=parseInt(document.getElementById('num-min')?.value||1);
  const mx=parseInt(document.getElementById('num-max')?.value||100);
  const q=Math.min(parseInt(document.getElementById('num-qty')?.value||10),1000);
  const uniq=document.getElementById('num-unique')?.checked;
  let pool=[];
  if(uniq){pool=Array.from({length:mx-mn+1},(_,i)=>i+mn);for(let i=pool.length-1;i>0;i--){const j=_rnd(0,i);[pool[i],pool[j]]=[pool[j],pool[i]];}pool=pool.slice(0,Math.min(q,pool.length));}
  else pool=Array.from({length:q},()=>_rnd(mn,mx));
  pool.sort((a,b)=>a-b);
  _renderBulkList('numeros', pool.map(String));
};


// ════════════════════════════════════════════════════════════════════════
//  PESSOA — RENDER COMPLETO
// ════════════════════════════════════════════════════════════════════════

function _genRender_pessoa(){
  const paisOpts=_PAIS_IDS.map(p=>`<option value="${p}">${_PAISES[p].bandeira} ${_PAISES[p].nome}</option>`).join('');
  const racaOpts=_RACAS.map(r=>`<option value="${r.id}">${r.pt}</option>`).join('');
  return`
  <div class="gen-top-bar"><h2>👤 Gerador de Pessoas</h2></div>
  <div class="gen-card">
    <div class="gen-bulk-row">
      <div class="gen-field-group"><label>País</label><select id="p-pais" class="gen-input"><option value="R">🌍 Aleatório</option>${paisOpts}</select></div>
      <div class="gen-field-group"><label>Gênero</label><select id="p-gen" class="gen-input"><option value="R">Aleatório</option><option value="M">Masculino</option><option value="F">Feminino</option><option value="NB">Não-binário</option><option value="TM">Trans Masc.</option><option value="TF">Trans Fem.</option></select></div>
      <div class="gen-field-group"><label>Raça/Etnia</label><select id="p-raca" class="gen-input"><option value="R">Aleatória</option>${racaOpts}</select></div>
      <div class="gen-field-group"><label>Quantidade</label><input type="number" id="p-qty" value="1" min="1" max="50" class="gen-input" style="width:80px"></div>
    </div>
    <div class="gen-bulk-actions" style="margin-top:12px">
      <button class="btn btn-primary" onclick="genExec_pessoa()">↻ Gerar Pessoa</button>
      <button class="btn btn-secondary" onclick="_bulkDownload('pessoa')">⬇ .TXT</button>
    </div>
  </div>
  <div id="pessoa-output"></div>`;
}

window.genExec_pessoa = function(){
  const paisId=document.getElementById('p-pais')?.value||'R';
  const genId=document.getElementById('p-gen')?.value||'R';
  const racId=document.getElementById('p-raca')?.value||'R';
  const qty=Math.min(parseInt(document.getElementById('p-qty')?.value||1),50);
  const pessoas=Array.from({length:qty},()=>_genPessoaCompleta(paisId==='R'?_pick(_PAIS_IDS):paisId,genId==='R'?null:genId,racId==='R'?null:racId));
  window._genBulkResults=pessoas.map(p=>JSON.stringify(p,null,2));
  const el=document.getElementById('pessoa-output');
  if(!el)return;
  el.innerHTML=pessoas.map(p=>_renderPessoaCard(p)).join('');
};

function _pF(label,value){
  return`<div class="gen-field"><span class="gen-field-label">${_esc(label)}</span><span class="gen-field-value">${_esc(String(value??'—'))}</span></div>`;
}
function _pSection(title,content){return`<div class="pessoa-section"><div class="pessoa-section-title">${title}</div>${content}</div>`;}

function _renderPessoaCard(p){
  const docs=Object.entries(p.documentos||{}).map(([k,v])=>_pF(k,v)).join('');
  const hobbies=(p.hobbies||[]).join(', ');
  const musica=(p.musica||[]).join(', ');
  const streaming=(p.streaming||[]).join(', ');
  return`
  <div class="gen-card pessoa-card" style="margin-bottom:16px">
    <div class="pessoa-header">
      <div class="pessoa-avatar">${p.nome_completo?.[0]||'?'}</div>
      <div>
        <div class="pessoa-nome">${_esc(p.nome_completo)}</div>
        <div class="pessoa-sub">${_esc(p.genero)} · ${_esc(p.raca)} · ${_esc(p.pais)}</div>
        <div class="pessoa-sub">${_esc(p.ocupacao)} @ ${_esc(p.empresa)}</div>
      </div>
    </div>
    <div class="pessoa-sections">
      ${_pSection('🪪 Identificação',_pF('Nome Completo',p.nome_completo)+_pF('Primeiro Nome',p.primeiro_nome)+_pF('Sobrenome',p.sobrenome)+_pF('Gênero',p.genero)+_pF('Raça/Etnia',p.raca)+_pF('País',p.pais)+_pF('Naturalidade',p.naturalidade)+_pF('Data de Nascimento',p.nascimento)+_pF('Idade',p.idade)+_pF('Signo',p.signo)+_pF('Tipo Sanguíneo',p.tipo_sanguineo)+_pF('Estado Civil',p.estado_civil)+_pF('Filhos',p.filhos))}
      ${_pSection('📞 Contato',_pF('Email Principal',p.email_principal)+_pF('Email Alternativo',p.email_alternativo)+_pF('Telefone',p.telefone)+_pF('Telefone 2',p.telefone_2))}
      ${_pSection('🏠 Endereço',_pF('Rua/Número',p.endereco)+_pF('Cidade',p.cidade)+_pF('Estado',p.estado)+_pF('CEP/ZIP',p.cep)+_pF('País',p.pais_nome))}
      ${_pSection('📋 Documentos',docs)}
      ${_pSection('🧬 Características Físicas',_pF('Altura',p.altura)+_pF('Peso',p.peso)+_pF('Cor dos Olhos',p.cor_olhos)+_pF('Tom de Pele',p.tom_pele)+_pF('Cor do Cabelo',p.cor_cabelo)+_pF('Tipo de Cabelo',p.tipo_cabelo))}
      ${_pSection('🧠 Personalidade',_pF('MBTI',p.mbti)+_pF('Linguagem do Amor',p.linguagem_amor)+_pF('Estilo de Aprendizado',p.estilo_aprendizado))}
      ${_pSection('💼 Profissional',_pF('Ocupação',p.ocupacao)+_pF('Área',p.area)+_pF('Empresa',p.empresa)+_pF('Escolaridade',p.escolaridade)+_pF('Renda',p.renda))}
      ${_pSection('❤️ Preferências',_pF('Cor Favorita',p.cor_favorita)+_pF('Estação do Ano',p.estacao_favorita)+_pF('Período do Dia',p.hora_preferida)+_pF('Comida Favorita',p.comida)+_pF('Fruta Favorita',p.fruta_favorita)+_pF('Intolerâncias',p.intolerancias)+_pF('Esporte',p.esporte)+_pF('Hobbies',hobbies)+_pF('Música',musica)+_pF('Gênero de Filme',p.filme)+_pF('Gênero de Livro',p.livro)+_pF('Streaming',streaming)+_pF('Rede Social',p.rede_social)+_pF('Pet',p.pet)+_pF('Estilo de Vida',p.estilo_vida)+_pF('Viagem',p.viagem))}
      ${_pSection('🕊️ Crenças',_pF('Religião',p.religiao)+_pF('Visão Política',p.politica))}
      ${_pSection('💻 Digital',_pF('Username',p.username)+_pF('Senha',p.senha)+_pF('IP',p.ip)+_pF('Moeda',p.moeda))}
    </div>
    <div style="margin-top:12px;display:flex;gap:8px">
      <button class="btn btn-secondary" onclick="_copyToClipboard(JSON.stringify(window._genBulkResults[0]||'',null,2))">📋 Copiar JSON</button>
    </div>
  </div>`;
}

// ─── Empresa + Currículo simplificados ───────────────────────────────
const _TIPOS_EMP=['Ltda','S.A.','MEI','ME','EPP'];
const _RAMOS=['Tecnologia','Comércio','Saúde','Educação','Consultoria','Logística'];
const _EMP_ADJ=['Digital','Solutions','Tech','Group','Systems','Prime','Global'];
const _EMP_N=['Alpha','Beta','Nova','Ultra','Star','Apex','Core','Edge'];
function _genEmpresa(){
  const tipo=_pick(_TIPOS_EMP),nome=`${_pick(_EMP_N)} ${_pick(_EMP_ADJ)}`;
  return{razao:`${nome} ${tipo}`,cnpj:_genCNPJ(true),ie:_genIE('SP',true).replace('/000',''),tipo,ramo:_pick(_RAMOS),email:`contato@${nome.toLowerCase().replace(/\s+/g,'')}.com.br`,telefone:_genPhone('BR'),cep:_genCEP(true)};
}
function _genRender_empresa(){return`
  <div class="gen-top-bar"><h2>🏭 Gerador de Empresas</h2></div>
  ${_bulkControls('empresa',false)}`;
}
window.genExec_empresa = function(){
  const q=parseInt(document.getElementById('empresa-qty')?.value||1);
  _renderBulkList('empresa',Array.from({length:q},()=>{const e=_genEmpresa();return`${e.razao} | CNPJ: ${e.cnpj} | ${e.ramo} | ${e.email}`;}));
};

const _SKILLS=[['JavaScript','React','Node.js','TypeScript'],['Python','Django','FastAPI','Docker'],['Java','Spring Boot','AWS','Kubernetes'],['PHP','Laravel','MySQL','Redis'],['C#','.NET','SQL Server','Azure']];
const _CARGOS=['Desenvolvedor(a) Pleno','Desenvolvedor(a) Sênior','Analista de Sistemas','Tech Lead','DevOps Engineer'];
const _EMP_JOBS=['TechCorp Brasil','Softex Solutions','CloudMaster S.A.','AgileWorks','ByteForce Digital'];
function _genRender_curriculo(){return`
  <div class="gen-top-bar"><h2>📋 Gerador de Currículo</h2></div>
  ${_bulkControls('curriculo',false,`<div class="gen-field-group"><label>País</label><select id="cv-pais" class="gen-input"><option value="R">Aleatório</option>${_PAIS_IDS.map(p=>`<option value="${p}">${_PAISES[p].bandeira} ${_PAISES[p].nome}</option>`).join('')}</select></div>`)}`;
}
window.genExec_curriculo = function(){
  const q=parseInt(document.getElementById('curriculo-qty')?.value||1);
  const pid=document.getElementById('cv-pais')?.value||'R';
  _renderBulkList('curriculo',Array.from({length:q},()=>{
    const p=_genPessoaCompleta(pid==='R'?_pick(_PAIS_IDS):pid);
    const sk=_pick(_SKILLS);
    const y=new Date().getFullYear();
    return`${p.nome_completo} | ${p.email_principal} | ${p.telefone} | ${p.cidade} | Habilidades: ${sk.join(', ')} | Cargo: ${_pick(_CARGOS)} @ ${_pick(_EMP_JOBS)} (${y-_rnd(1,3)}–Atual)`;
  }));
};

// ════════════════════════════════════════════════════════════════════════
//  PAGE ROUTING
// ════════════════════════════════════════════════════════════════════════

function showGeneratorsPage(){
  const view=document.getElementById('view-generators');
  if(!view)return;
  if(!document.getElementById('gen-sidebar')){
    view.innerHTML=`
      <div class="gen-layout">
        <aside class="gen-sidebar" id="gen-sidebar">
          <div class="gen-sidebar-search">
            <input type="text" placeholder="Filtrar..." id="gen-filter-input" oninput="genFilterSidebar()" autocomplete="off">
          </div>
          <div id="gen-sidebar-list">
            ${GEN_MODULES.map(m=>`<button class="gen-nav-item ${m.id===_genActive?'active':''}" id="gen-nav-${m.id}" onclick="genActivate('${m.id}')"><span class="gen-nav-icon">${m.icon}</span><span class="gen-nav-label">${m.label}</span></button>`).join('')}
          </div>
        </aside>
        <main class="gen-main" id="gen-main"></main>
      </div>`;
  }
  genActivate(_genActive);
}

function genFilterSidebar(){
  const q=(document.getElementById('gen-filter-input')?.value||'').toLowerCase();
  GEN_MODULES.forEach(m=>{const el=document.getElementById(`gen-nav-${m.id}`);if(el)el.style.display=(!q||m.label.toLowerCase().includes(q))?'':'none';});
}

function genActivate(id){
  _genActive=id;
  document.querySelectorAll('.gen-nav-item').forEach(el=>el.classList.remove('active'));
  document.getElementById(`gen-nav-${id}`)?.classList.add('active');
  const main=document.getElementById('gen-main'); if(!main)return;
  const renders={cpf:_genRender_cpf,cnpj:_genRender_cnpj,rg:_genRender_rg,cep:_genRender_cep,pis:_genRender_pis,renavam:_genRender_renavam,cnh:_genRender_cnh,titulo:_genRender_titulo,ie:_genRender_ie,cartao:_genRender_cartao,placa:_genRender_placa,veiculo:_genRender_veiculo,conta:_genRender_conta,certidao:_genRender_certidao,pessoa:_genRender_pessoa,empresa:_genRender_empresa,curriculo:_genRender_curriculo,nome:_genRender_nome,nick:_genRender_nick,numeros:_genRender_numeros,senha:_genRender_senha};
  const fn=renders[id]; if(fn)main.innerHTML=fn();
  if(id==='letras')genUpdateLetras();
}
