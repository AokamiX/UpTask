const mobileMenuBtn=document.querySelector("#mobile-menu"),cerrarMenuBtn=document.querySelector("#cerrar-menu"),sideBar=document.querySelector(".sidebar");mobileMenuBtn&&mobileMenuBtn.addEventListener("click",(function(){sideBar.classList.add("mostrar"),sideBar.classList.add("mostrar")})),cerrarMenuBtn&&cerrarMenuBtn.addEventListener("click",(function(){sideBar.classList.add("ocultar"),setTimeout(()=>{sideBar.classList.remove("mostrar"),sideBar.classList.remove("ocultar")},1e3)}));const anchoPantalla=document.body.clientWidth;window.addEventListener("resize",(function(){document.body.clientWidth>=768&&sideBar.classList.remove("mostrar")}));