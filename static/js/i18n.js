/* i18n.js — Language switcher for Scantrely.
 *
 * Strings live in I18N_STRINGS[key] = {en, "pt-br", es}. Elements opt in via:
 *   data-i18n-key="some_key"          -> sets textContent
 *   data-i18n-placeholder="some_key"  -> sets placeholder attribute
 *   data-i18n-title="some_key"        -> sets title attribute
 *
 * Call window.applyI18n() after rendering dynamic content (the new
 * "Bug Bounty Helper" / "External Tools" tabs use this) and use
 * window.t(key) to look up a translated string from JS.
 */

window.I18N_STRINGS = {
  app_name:            {en:"SCANTRELY", "pt-br":"SCANTRELY", es:"SCANTRELY"},

  // Sidebar
  nav_workspace:       {en:"Workspace", "pt-br":"Workspace", es:"Workspace"},
  nav_all:             {en:"All Companies", "pt-br":"Todas as Empresas", es:"Todas las Empresas"},
  nav_jobs:            {en:"Job Queue", "pt-br":"Fila de Jobs", es:"Cola de Trabajos"},
  nav_companies:       {en:"Companies", "pt-br":"Empresas", es:"Empresas"},
  add_company_button:  {en:"＋ Add Company", "pt-br":"＋ Adicionar Empresa", es:"＋ Agregar Empresa"},
  nav_admin:           {en:"Admin", "pt-br":"Admin", es:"Admin"},
  nav_admins:          {en:"Manage Admins", "pt-br":"Gerenciar Admins", es:"Gestionar Admins"},
  nav_tools:           {en:"Tools", "pt-br":"Ferramentas", es:"Herramientas"},
  nav_bbhelper:        {en:"Bug Bounty Helper", "pt-br":"Bug Bounty Helper", es:"Bug Bounty Helper"},
  nav_exttools:        {en:"External Tools", "pt-br":"Ferramentas Externas", es:"Herramientas Externas"},
  nav_settings:        {en:"API Keys", "pt-br":"Chaves de API", es:"Claves de API"},
  nav_runtime:         {en:"Performance", "pt-br":"Performance", es:"Rendimiento"},
  nav_logout:          {en:"Sign Out", "pt-br":"Sair", es:"Salir"},

  // Topbar
  topbar_tagline:      {en:"EXTERNAL ATTACK SURFACE MONITORING", "pt-br":"MONITORAMENTO DE SUPERFÍCIE DE ATAQUE EXTERNA", es:"MONITOREO DE SUPERFICIE DE ATAQUE EXTERNA"},
  crumb_dashboard:     {en:"Dashboard", "pt-br":"Dashboard", es:"Dashboard"},
  search_label:        {en:"Search...", "pt-br":"Buscar...", es:"Buscar..."},
  new_scan_btn:        {en:"New Scan", "pt-br":"Novo Scan", es:"Nuevo Escaneo"},

  // All Companies view
  view_all_title:      {en:"All Companies", "pt-br":"Todas as Empresas", es:"Todas las Empresas"},
  view_all_empty_title:{en:"No companies yet", "pt-br":"Nenhuma empresa ainda", es:"Aún no hay empresas"},
  view_all_empty_desc: {en:"Add a company and run a scan to start mapping attack surfaces.", "pt-br":"Adicione uma empresa e execute um scan para começar a mapear superfícies de ataque.", es:"Agregue una empresa y ejecute un escaneo para empezar a mapear superficies de ataque."},

  // Company view action buttons
  btn_edit_scope:      {en:"✏ Edit Scope", "pt-br":"✏ Editar Escopo", es:"✏ Editar Alcance"},
  btn_export_html:     {en:"📄 Export Report", "pt-br":"📄 Exportar Relatório", es:"📄 Exportar Informe"},
  btn_export_pdf:      {en:"🖨 Export PDF", "pt-br":"🖨 Exportar PDF", es:"🖨 Exportar PDF"},
  btn_clear_data:      {en:"🗑 Clear Data", "pt-br":"🗑 Limpar Dados", es:"🗑 Borrar Datos"},

  // Company tab bar
  tab_overview:        {en:"Overview", "pt-br":"Visão Geral", es:"Resumen"},
  tab_hosts:           {en:"Hosts", "pt-br":"Hosts", es:"Hosts"},
  tab_vulns:           {en:"Vulnerabilities", "pt-br":"Vulnerabilidades", es:"Vulnerabilidades"},
  tab_infra:           {en:"Infrastructure", "pt-br":"Infraestrutura", es:"Infraestructura"},
  tab_recon:           {en:"Recon", "pt-br":"Recon", es:"Recon"},
  tab_operation:       {en:"Operation", "pt-br":"Operação", es:"Operación"},
  tab_logs:            {en:"Logs", "pt-br":"Logs", es:"Logs"},
  tab_pipeline:        {en:"Pipeline", "pt-br":"Pipeline", es:"Pipeline"},

  // Settings view
  settings_title:      {en:"⚙ API Keys & Settings", "pt-br":"⚙ Chaves de API & Configurações", es:"⚙ Claves de API y Configuración"},
  settings_desc:       {en:"Configure third-party intelligence APIs used by the recon modules.", "pt-br":"Configure as APIs de inteligência de terceiros usadas pelos módulos de recon.", es:"Configure las APIs de inteligencia de terceros usadas por los módulos de recon."},
  settings_unsaved:    {en:"Unsaved changes will be applied when you click Save.", "pt-br":"Alterações não salvas serão aplicadas ao clicar em Salvar.", es:"Los cambios sin guardar se aplicarán al hacer clic en Guardar."},
  btn_reload:          {en:"↺ Reload", "pt-br":"↺ Recarregar", es:"↺ Recargar"},
  btn_save_settings:   {en:"💾 Save All Settings", "pt-br":"💾 Salvar Configurações", es:"💾 Guardar Configuración"},
  webhooks_title:      {en:"🔔 Notifications / Webhooks", "pt-br":"🔔 Notificações / Webhooks", es:"🔔 Notificaciones / Webhooks"},
  webhooks_desc:       {en:"Get alerts for scan completion (scan_complete) and critical findings (critical_finding) via Telegram, Discord, Slack, WhatsApp, Signal, Email or CLI. One agent, one memory, every surface.", "pt-br":"Receba alertas de fim de scan (scan_complete) e findings críticos (critical_finding) via Telegram, Discord, Slack, WhatsApp, Signal, Email ou CLI. One agent, one memory, every surface.", es:"Recibe alertas de fin de escaneo (scan_complete) y hallazgos críticos (critical_finding) vía Telegram, Discord, Slack, WhatsApp, Signal, Email o CLI. One agent, one memory, every surface."},
  webhooks_add_title:  {en:"➕ Add Webhook", "pt-br":"➕ Adicionar Webhook", es:"➕ Agregar Webhook"},
  webhooks_platform:   {en:"Platform", "pt-br":"Plataforma", es:"Plataforma"},
  webhooks_events:     {en:"Events", "pt-br":"Eventos", es:"Eventos"},
  btn_add_webhook:     {en:"Add Webhook", "pt-br":"Adicionar Webhook", es:"Agregar Webhook"},

  // Runtime view
  runtime_title:       {en:"⚡ Performance & Concurrency", "pt-br":"⚡ Performance & Concorrência", es:"⚡ Rendimiento y Concurrencia"},
  runtime_desc:        {en:"Controls workers, process limits, watchdog and rate limiting. Requires server restart to apply.", "pt-br":"Controla workers, limites de processos, watchdog e rate limiting. Requer restart do servidor para aplicar.", es:"Controla workers, límites de procesos, watchdog y límites de tasa. Requiere reiniciar el servidor para aplicar."},
  runtime_ready:       {en:"Ready", "pt-br":"Pronto", es:"Listo"},
  btn_save_config:     {en:"💾 Save Config", "pt-br":"💾 Salvar Config", es:"💾 Guardar Config"},

  // Jobs view
  jobs_kicker:         {en:"Operations", "pt-br":"Operação", es:"Operaciones"},
  jobs_title:          {en:"Job Queue", "pt-br":"Fila de Jobs", es:"Cola de Trabajos"},
  jobs_desc:           {en:"Track what's running now, the per-company backlog and the queue history.", "pt-br":"Acompanhe o que está rodando agora, o backlog por empresa e o histórico da fila.", es:"Sigue lo que se está ejecutando ahora, el backlog por empresa y el historial de la cola."},
  jobs_filter_all_types: {en:"All Types", "pt-br":"Todos os Tipos", es:"Todos los Tipos"},
  jobs_filter_all_status:{en:"All Status", "pt-br":"Todos os Status", es:"Todos los Estados"},
  jobs_status_running:  {en:"Running now", "pt-br":"Rodando agora", es:"Ejecutando ahora"},
  jobs_status_pending:  {en:"Pending", "pt-br":"Pendente", es:"Pendiente"},
  jobs_status_done:     {en:"Done", "pt-br":"Concluído", es:"Completado"},
  jobs_status_error:    {en:"Error", "pt-br":"Erro", es:"Error"},
  jobs_status_stopped:  {en:"Stopped", "pt-br":"Parado", es:"Detenido"},
  jobs_status_cancelled:{en:"Cancelled", "pt-br":"Cancelado", es:"Cancelado"},
  btn_refresh:          {en:"Refresh", "pt-br":"Atualizar", es:"Actualizar"},
  jobs_table_title:     {en:"Jobs", "pt-br":"Jobs", es:"Trabajos"},
  jobs_th_status:       {en:"Status", "pt-br":"Status", es:"Estado"},
  jobs_th_target:       {en:"Domain / Subdomain", "pt-br":"Domínio / Subdomínio", es:"Dominio / Subdominio"},
  jobs_th_type:         {en:"Type", "pt-br":"Tipo", es:"Tipo"},
  jobs_th_created:      {en:"Created", "pt-br":"Criado", es:"Creado"},
  jobs_th_started:      {en:"Started", "pt-br":"Iniciado", es:"Iniciado"},
  jobs_th_finished:     {en:"Finished", "pt-br":"Finalizado", es:"Finalizado"},
  jobs_th_attempts:     {en:"Attempts", "pt-br":"Tentativas", es:"Intentos"},
  jobs_th_actions:      {en:"Actions", "pt-br":"Ações", es:"Acciones"},
  jobs_clear_filtered:  {en:"Clear records", "pt-br":"Limpar registros", es:"Borrar registros"},
  jobs_refresh_queue:   {en:"Refresh queue", "pt-br":"Atualizar fila", es:"Actualizar cola"},

  // Tools view
  tools_title:        {en:"🔧 Tool Registry", "pt-br":"🔧 Registro de Ferramentas", es:"🔧 Registro de Herramientas"},
  tools_desc:         {en:"All recon tools — status, versions, and one-click runs.", "pt-br":"Todas as ferramentas de recon — status, versões e execução com um clique.", es:"Todas las herramientas de recon — estado, versiones y ejecución con un clic."},
  tools_all_categories:{en:"All Categories", "pt-br":"Todas as Categorias", es:"Todas las Categorías"},
  tools_all_status:    {en:"All Status", "pt-br":"Todos os Status", es:"Todos los Estados"},

  // Admins view
  admins_title:       {en:"👥 Admin Accounts", "pt-br":"👥 Contas de Administrador", es:"👥 Cuentas de Administrador"},
  admins_desc:        {en:"Manage who has access to the ASM Platform.", "pt-br":"Gerencie quem tem acesso à plataforma ASM.", es:"Gestiona quién tiene acceso a la plataforma ASM."},
  btn_add_admin:      {en:"＋ Add Admin", "pt-br":"＋ Adicionar Admin", es:"＋ Agregar Admin"},
  admins_th_username: {en:"Username", "pt-br":"Usuário", es:"Usuario"},
  admins_th_email:    {en:"Email", "pt-br":"Email", es:"Email"},
  admins_th_role:     {en:"Role", "pt-br":"Função", es:"Rol"},
  admins_th_created:  {en:"Created", "pt-br":"Criado", es:"Creado"},
  admins_th_lastlogin:{en:"Last Login", "pt-br":"Último Login", es:"Último Acceso"},
  admins_th_actions:  {en:"Actions", "pt-br":"Ações", es:"Acciones"},

  // ── Bug Bounty Helper ──
  bbh_title:          {en:"🎯 Bug Bounty Helper", "pt-br":"🎯 Bug Bounty Helper", es:"🎯 Bug Bounty Helper"},
  bbh_desc:           {en:"Google Dorks and OSINT shortcuts for a target domain — click a module to open the right search engine / service.", "pt-br":"Google Dorks e atalhos OSINT para um domínio alvo — clique em um módulo para abrir o mecanismo de busca / serviço correto.", es:"Google Dorks y accesos directos OSINT para un dominio objetivo — haz clic en un módulo para abrir el motor de búsqueda / servicio correcto."},
  bbh_domain_placeholder: {en:"example.com", "pt-br":"example.com", es:"example.com"},
  bbh_domain_tip:     {en:"TIP: Add ?d=example.com to the URL to auto-load a domain", "pt-br":"DICA: Adicione ?d=example.com na URL para carregar o domínio automaticamente", es:"CONSEJO: Agrega ?d=example.com a la URL para cargar el dominio automáticamente"},
  bbh_cat_all:        {en:"All Modules", "pt-br":"Todos os Módulos", es:"Todos los Módulos"},
  bbh_cat_dorks:      {en:"Google Dorks", "pt-br":"Google Dorks", es:"Google Dorks"},
  bbh_cat_recon:      {en:"Recon & Subdomains", "pt-br":"Recon & Subdomínios", es:"Recon y Subdominios"},
  bbh_cat_archives:   {en:"Archives & History", "pt-br":"Arquivos & Histórico", es:"Archivos e Historial"},
  bbh_cat_intel:      {en:"OSINT & Intelligence", "pt-br":"OSINT & Inteligência", es:"OSINT e Inteligencia"},
  bbh_cat_files:      {en:"Specific Files", "pt-br":"Arquivos Específicos", es:"Archivos Específicos"},
  bbh_enter_domain:   {en:"Enter a domain above first.", "pt-br":"Informe um domínio acima primeiro.", es:"Ingresa un dominio arriba primero."},

  // ── External Tools ──
  ext_title:          {en:"✦ External Tools", "pt-br":"✦ Ferramentas Externas", es:"✦ Herramientas Externas"},
  ext_desc:           {en:"One-click shortcuts to external recon, OSINT and utility tools used during bug bounty engagements.", "pt-br":"Atalhos com um clique para ferramentas externas de recon, OSINT e utilitários usados em engajamentos de bug bounty.", es:"Accesos directos a herramientas externas de recon, OSINT y utilidades usadas en programas de bug bounty."},

  // ── Dynamic status / feedback strings ──
  settings_loaded:       {en:"Settings loaded from server", "pt-br":"Configurações carregadas do servidor", es:"Configuración cargada del servidor"},
  config_loaded:         {en:"Config loaded from server",   "pt-br":"Config carregada do servidor",   es:"Configuración cargada del servidor"},
  settings_unsaved_mod:  {en:"Unsaved changes",             "pt-br":"Alterações não salvas",          es:"Cambios sin guardar"},
  settings_saved_ok:     {en:"✓ Settings saved",            "pt-br":"✓ Configurações salvas",         es:"✓ Configuración guardada"},
  settings_save_err:     {en:"Error saving settings",       "pt-br":"Erro ao salvar configurações",   es:"Error al guardar configuración"},
  settings_conn_err:     {en:"Connection error",            "pt-br":"Erro de conexão",                es:"Error de conexión"},
  settings_demo_mode:    {en:"Demo mode — settings not persisted", "pt-br":"Modo demo — configurações não salvas", es:"Modo demo — configuración no guardada"},
  config_saved_ok:       {en:"✓ Config saved — restart server to apply", "pt-br":"✓ Config salva — reinicie o servidor para aplicar", es:"✓ Config guardada — reinicie el servidor para aplicar"},
  config_save_err:       {en:"Error saving config",         "pt-br":"Erro ao salvar config",          es:"Error al guardar config"},

  // ── Breadcrumbs ──
  crumb_jobs:     {en:"Job Queue",        "pt-br":"Fila de Jobs",     es:"Cola de Trabajos"},
  crumb_tools:    {en:"Tools",            "pt-br":"Ferramentas",      es:"Herramientas"},
  crumb_settings: {en:"API Keys",         "pt-br":"Chaves de API",    es:"Claves de API"},
  crumb_runtime:  {en:"Performance",      "pt-br":"Performance",      es:"Rendimiento"},
  crumb_admins:   {en:"Admin",            "pt-br":"Admin",            es:"Admin"},
  crumb_bbhelper: {en:"Bug Bounty Helper","pt-br":"Bug Bounty Helper","es":"Bug Bounty Helper"},
  crumb_exttools: {en:"External Tools",   "pt-br":"Ferramentas Externas","es":"Herramientas Externas"},
};

window.t = function(key) {
  const lang = localStorage.getItem('lang') || 'pt-br';
  const entry = window.I18N_STRINGS[key];
  if (!entry) return key;
  return entry[lang] || entry.en || entry["pt-br"] || key;
};

window.setLanguage = function(lang) {
  localStorage.setItem('lang', lang);
  window.applyI18n();
};

window.applyI18n = function() {
  const lang = localStorage.getItem('lang') || 'pt-br';
  document.documentElement.lang = lang;

  document.querySelectorAll('[data-i18n-key]').forEach(function(el) {
    const key = el.getAttribute('data-i18n-key');
    const val = window.t(key);
    if (val !== key) el.textContent = val;
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(function(el) {
    const key = el.getAttribute('data-i18n-placeholder');
    const val = window.t(key);
    if (val !== key) el.setAttribute('placeholder', val);
  });
  document.querySelectorAll('[data-i18n-title]').forEach(function(el) {
    const key = el.getAttribute('data-i18n-title');
    const val = window.t(key);
    if (val !== key) el.setAttribute('title', val);
  });

  const sel = document.getElementById('lang-select');
  if (sel) sel.value = lang;
};

document.addEventListener('DOMContentLoaded', function() {
  window.applyI18n();
});
