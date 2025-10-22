// Indicator simplu pe request HTMX
document.addEventListener('htmx:configRequest', function (evt) {
  // include și campurile cu id specificate în hx-include (fallback pentru unele browsere)
});

document.addEventListener('htmx:beforeRequest', function(){
  document.body.classList.add('loading');
});

document.addEventListener('htmx:afterRequest', function(){
  document.body.classList.remove('loading');
});
