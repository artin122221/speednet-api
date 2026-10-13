<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Speed Net | WireGuard</title>

<style>
:root{
  --bg:#07070b;
  --card:#11111a;
  --line:#292936;
  --gold:#eab308;
  --purple:#8b5cf6;
  --text:#f5f5f5;
  --muted:#9ca3af;
  --green:#22c55e;
  --red:#ef4444;
}

*{
  box-sizing:border-box;
}

body{
  margin:0;
  min-height:100vh;
  background:
    radial-gradient(circle at 50% -10%,#2a1a45 0,#0b0b11 42%,#050507 100%);
  color:var(--text);
  font-family:Tahoma,Arial,sans-serif;
}

.hidden{
  display:none!important;
}

/* LOGIN */

.login{
  min-height:100vh;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:20px;
}

.login-box{
  width:100%;
  max-width:430px;
  background:rgba(17,17,26,.95);
  border:1px solid #342d49;
  border-radius:26px;
  padding:30px;
  text-align:center;
  box-shadow:0 25px 80px #0009;
}

.logo{
  width:82px;
  height:82px;
  margin:0 auto 16px;
  border-radius:24px;
  display:grid;
  place-items:center;
  background:linear-gradient(135deg,var(--gold),var(--purple));
  color:#111;
  font-size:40px;
  font-weight:900;
  box-shadow:0 10px 35px #8b5cf655;
}

.login-title{
  font-size:27px;
  font-weight:900;
  margin-bottom:5px;
}

.login-sub{
  color:var(--muted);
  font-size:13px;
}

.input{
  width:100%;
  margin:20px 0 12px;
  padding:15px;
  border-radius:14px;
  border:1px solid var(--line);
  outline:none;
  background:#08080d;
  color:white;
  font-size:15px;
  text-align:center;
}

.input:focus{
  border-color:var(--gold);
}

.btn{
  border:0;
  border-radius:13px;
  padding:13px 17px;
  font-weight:800;
  cursor:pointer;
  transition:.2s;
}

.btn:hover{
  transform:translateY(-1px);
}

.primary{
  width:100%;
  background:linear-gradient(135deg,var(--gold),#f59e0b);
  color:#111;
}

.ghost{
  background:#181820;
  border:1px solid var(--line);
  color:white;
}

.danger{
  background:#35151b;
  color:#fecaca;
  border:1px solid #5b2029;
}

.error{
  min-height:20px;
  margin-top:10px;
  color:#f87171;
  font-size:13px;
}

/* PANEL */

.wrap{
  width:100%;
  max-width:950px;
  margin:auto;
  padding:18px;
}

header{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:15px;
  margin-bottom:18px;
}

.brand{
  font-size:24px;
  font-weight:900;
}

.brand span{
  color:var(--gold);
}

.subtitle{
  color:var(--muted);
  font-size:12px;
  margin-top:4px;
}

.status{
  padding:8px 12px;
  border-radius:999px;
  background:#0d2817;
  color:#86efac;
  border:1px solid #1e5b30;
  font-size:12px;
  white-space:nowrap;
}

/* NAV */

nav{
  display:flex;
  gap:8px;
  overflow-x:auto;
  margin-bottom:16px;
  padding-bottom:2px;
}

nav button{
  white-space:nowrap;
  padding:11px 16px;
  border-radius:12px;
  border:1px solid var(--line);
  background:#11111a;
  color:#aaa;
  cursor:pointer;
}

nav button.active{
  background:var(--gold);
  border-color:var(--gold);
  color:#111;
  font-weight:900;
}

/* CARDS */

.grid{
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}

.card{
  background:rgba(17,17,26,.92);
  border:1px solid var(--line);
  border-radius:19px;
  padding:18px;
  box-shadow:0 8px 30px #0003;
}

.full{
  grid-column:1/-1;
}

.label{
  color:var(--muted);
  font-size:12px;
  margin-bottom:8px;
}

.value{
  font-weight:800;
  word-break:break-all;
}

.pill{
  display:inline-block;
  padding:6px 10px;
  border-radius:999px;
  background:#211b08;
  color:#fde68a;
  border:1px solid #5a470b;
  font-size:12px;
}

.actions{
  display:flex;
  gap:9px;
  flex-wrap:wrap;
  margin-top:14px;
}

.actions .btn{
  flex:1;
  min-width:130px;
}

/* CONFIG */

.code{
  direction:ltr;
  text-align:left;
  white-space:pre-wrap;
  overflow:auto;
  background:#060609;
  border:1px solid #282832;
  border-radius:15px;
  padding:16px;
  min-height:280px;
  font-family:monospace;
  font-size:12px;
  line-height:1.7;
  color:#ddd;
}

.notice{
  margin-top:12px;
  padding:12px;
  border-radius:12px;
  background:#17130a;
  border:1px solid #4d3b08;
  color:#fde68a;
  font-size:12px;
  line-height:1.8;
}

/* MOBILE */

@media(max-width:650px){
  .wrap{
    padding:12px;
  }

  .grid{
    grid-template-columns:1fr;
  }

  .full{
    grid-column:auto;
  }

  header{
    align-items:flex-start;
  }

  .brand{
    font-size:21px;
  }

  .status{
    font-size:11px;
  }
}
</style>
</head>

<body>

<!-- =========================
     LOGIN
========================= -->

<section id="loginPage" class="login">

  <div class="login-box">

    <div class="logo">S</div>

    <div class="login-title">
      SPEED NET
    </div>

    <div class="login-sub">
      پنل خصوصی WireGuard
    </div>

    <input
      id="passwordInput"
      class="input"
      type="password"
      placeholder="رمز ورود"
      autocomplete="off"
      onkeydown="if(event.key==='Enter') login()"
    >

    <button
      class="btn primary"
      onclick="login()"
    >
      ورود به پنل
    </button>

    <div id="loginError" class="error"></div>

  </div>

</section>


<!-- =========================
     MAIN PANEL
========================= -->

<main id="panelPage" class="wrap hidden">

  <header>

    <div>
      <div class="brand">
        SPEED <span>NET</span>
      </div>

      <div class="subtitle">
        WireGuard Management Panel
      </div>
    </div>

    <div class="status">
      ● آنلاین
    </div>

  </header>


  <!-- NAVIGATION -->

  <nav>

    <button
      class="active"
      onclick="showTab('dashboard',this)"
    >
      داشبورد
    </button>

    <button
      onclick="showTab('config',this)"
    >
      کانفیگ
    </button>

    <button
      onclick="showTab('info',this)"
    >
      اطلاعات
    </button>

  </nav>


  <!-- =========================
       DASHBOARD
  ========================= -->

  <section id="dashboard" class="tab">

    <div class="grid">

      <div class="card">
        <div class="label">
          Endpoint
        </div>

        <div class="value">
          8.6.112.165:928
        </div>
      </div>


      <div class="card">
        <div class="label">
          Address
        </div>

        <div class="value">
          172.16.0.2/32
        </div>
      </div>


      <div class="card">
        <div class="label">
          DNS
        </div>

        <div class="value">
          1.1.1.1, 8.8.8.8
        </div>
      </div>


      <div class="card">
        <div class="label">
          MTU
        </div>

        <div class="value">
          1320
        </div>
      </div>


      <div class="card full">

        <div class="label">
          Allowed IPs
        </div>

        <div class="value">
          0.0.0.0/0
        </div>

      </div>


      <div class="card full">

        <span class="pill">
          SPEED NET
        </span>

        <h3 style="margin-top:15px">
          کانفیگ آماده اتصال
        </h3>

        <div class="actions">

          <button
            class="btn primary"
            onclick="downloadConfig()"
          >
            دانلود کانفیگ
          </button>

          <button
            class="btn ghost"
            onclick="copyConfig()"
          >
            کپی کانفیگ
          </button>

          <button
            class="btn danger"
            onclick="logout()"
          >
            خروج
          </button>

        </div>

      </div>

    </div>

  </section>


  <!-- =========================
       CONFIG
  ========================= -->

  <section id="config" class="tab hidden">

    <div class="card">

      <h2>
        WireGuard Config
      </h2>

      <p class="subtitle">
        کانفیگ فعلی پنل
      </p>

      <div
        id="configCode"
        class="code"
      ></div>


      <div class="actions">

        <button
          class="btn primary"
          onclick="downloadConfig()"
        >
          دانلود فایل .conf
        </button>

        <button
          class="btn ghost"
          onclick="copyConfig()"
        >
          کپی کانفیگ
        </button>

      </div>


      <div class="notice">
        کلید خصوصی را فقط روی دستگاه خودت نگه دار.
        این صفحه به‌تنهایی سرور WireGuard را مدیریت نمی‌کند.
      </div>

    </div>

  </section>


  <!-- =========================
       INFO
  ========================= -->

  <section id="info" class="tab hidden">

    <div class="card">

      <h2>
        اطلاعات Speed Net
      </h2>

      <p class="subtitle">
        این نسخه یک پنل HTML محلی برای نمایش و دانلود کانفیگ WireGuard است.
      </p>

      <br>

      <div class="label">
        Server
      </div>

      <div class="value">
        8.6.112.165:928
      </div>

      <br>

      <div class="label">
        Protocol
      </div>

      <div class="value">
        WireGuard
      </div>

      <br>

      <div class="label">
        DNS
      </div>

      <div class="value">
        1.1.1.1 / 8.8.8.8
      </div>

      <br>

      <div class="label">
        MTU
      </div>

      <div class="value">
        1320
      </div>

    </div>

  </section>

</main>


<script>

/* =========================
   SETTINGS
========================= */

/*
  رمز ورود پنل
*/
const PASSWORD = "speed net";


/*
  کلید خصوصی را فقط روی دستگاه خودت وارد کن.

  چون کلید خصوصی قبلی در چت ارسال شده،
  آن را عمداً داخل این فایل قرار نداده‌ایم.

  مقدار زیر را با PrivateKey خودت جایگزین کن.
*/
const PRIVATE_KEY =
"PUT_YOUR_PRIVATE_KEY_HERE";


/*
  Public Key سرور
*/
const SERVER_PUBLIC_KEY =
"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";


/*
  مشخصات کانفیگ
*/
const SERVER_ENDPOINT =
"8.6.112.165:928";

const CLIENT_ADDRESS =
"172.16.0.2/32";

const DNS =
"1.1.1.1, 8.8.8.8";

const MTU =
"1320";

const ALLOWED_IPS =
"0.0.0.0/0";


/* =========================
   CREATE CONFIG
========================= */

function getConfig(){

  return `# =========================================
# SPEED NET | WireGuard
# =========================================

[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = ${CLIENT_ADDRESS}
DNS = ${DNS}
MTU = ${MTU}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
AllowedIPs = ${ALLOWED_IPS}
Endpoint = ${SERVER_ENDPOINT}
`;

}


/* =========================
   LOGIN
========================= */

function login(){

  const input =
    document.getElementById("passwordInput");

  const error =
    document.getElementById("loginError");

  if(input.value === PASSWORD){

    sessionStorage.setItem(
      "speednet_logged_in",
      "1"
    );

    document
      .getElementById("loginPage")
      .classList.add("hidden");

    document
      .getElementById("panelPage")
      .classList.remove("hidden");

    renderConfig();

    error.textContent = "";

  }else{

    error.textContent =
      "رمز ورود اشتباه است.";

    input.value = "";

    input.focus();

  }

}


/* =========================
   LOGOUT
========================= */

function logout(){

  sessionStorage.removeItem(
    "speednet_logged_in"
  );

  location.reload();

}


/* =========================
   RENDER CONFIG
========================= */

function renderConfig(){

  const box =
    document.getElementById("configCode");

  box.textContent =
    getConfig();

}


/* =========================
   TABS
========================= */

function showTab(id, button){

  document
    .querySelectorAll(".tab")
    .forEach(tab => {

      tab.classList.add("hidden");

    });


  document
    .getElementById(id)
    .classList.remove("hidden");


  document
    .querySelectorAll("nav button")
    .forEach(btn => {

      btn.classList.remove("active");

    });


  button.classList.add("active");

}


/* =========================
   COPY CONFIG
========================= */

async function copyConfig(){

  const config =
    getConfig();

  try{

    await navigator.clipboard.writeText(config);

    alert("کانفیگ با موفقیت کپی شد.");

  }catch(error){

    prompt(
      "کانفیگ را کپی کن:",
      config
    );

  }

}


/* =========================
   DOWNLOAD CONFIG
========================= */

function downloadConfig(){

  const config =
    getConfig();

  const blob =
    new Blob(
      [config],
      {
        type:"text/plain;charset=utf-8"
      }
    );

  const url =
    URL.createObjectURL(blob);

  const link =
    document.createElement("a");

  link.href = url;

  link.download =
    "speed-net.conf";

  document.body.appendChild(link);

  link.click();

  link.remove();

  setTimeout(
    () => URL.revokeObjectURL(url),
    1000
  );

}


/* =========================
   AUTO LOGIN
========================= */

if(
  sessionStorage.getItem(
    "speednet_logged_in"
  ) === "1"
){

  document
    .getElementById("loginPage")
    .classList.add("hidden");

  document
    .getElementById("panelPage")
    .classList.remove("hidden");

  renderConfig();

}

</script>

</body>
</html>
