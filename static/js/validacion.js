

function validarFormulario(){
    var user = document.formulario.username;
    var email = document.formulario.email;
    var passwd= document.formulario.password;

    var userLen = user.value.length;
    if(userlen == 0 || userLen<8){
        alert("Debe ingresar un usuario con minimo 8 caracteres")
    } else {
        console.log("Paso la prueba");
    }
    var passwdLen = passwd.value.length;
    if (passwdLen ==0 || passwdLen<8) {
        alert("Ingresar una clave con más de 8 caracteres");
    } else {
        console.log("Paso prueba de la contraseña");
    }

    var emailFormat = /^\w+([\.-]?\w+)@\w+([\.-]?\w+)(\.\w{2,3})+$/;

    if(!email.value.match(emailFormat)){
        alert("Debes ingresar un correo válido!");
    }else{
        console.log("Paso prueba del correo");
    }
}

function validarProducto(){
    var beverage = document.getElementById("Nombre").value;
    img = document.createElement("img");
    contenedor = document.getElementById("contenedor");
    //console.log(beverage.type)
    if (beverage === "Capuccino") {
        console.log("ASDSAD")
        img.src = "../static/images/capuccino.png"
        contenedor.appendChild(img);
        //img src="images/Capuccino.jpg";
    }else if (beverage === "Latte") {
        console.log("ASDSAD")
        img.src = "../static/images/latte.png"
        contenedor.appendChild(img);
            //img src="images/Latte.jpg";
    }else if (beverage === "Malteada") {
        console.log("ASDSAD")
        img.src = "../static/images/malteada.png"
        contenedor.appendChild(img);
            //img src="images/malteada.png";
    }else if (beverage === "Mocaccino") {
        console.log("ASDSAD")
        img.src = "../static/images/mocaccino.png"
        contenedor.appendChild(img);
            //img src="images/mocaccino.png";
    }else if (beverage === "Granizado"){
        console.log("ASDSAD")
        img.src = "../static/images/granizado.png"
        contenedor.appendChild(img);
        //img src="images/granizado.png";
    }else if (beverage === "Chocolate"){
        console.log("ASDSAD")
        img.src = "../static/images/chocolate.png"
        contenedor.appendChild(img);
    }else{
        console.log("ASDSAD")
        img.src = "../static/images/fondo.png"
        contenedor.appendChild(img);
    }

}

function showPassword(){
    var elemento = document.getElementById('password');
    elemento.type = "text";
}

function hidePassword(){
    var elemento = document.getElementById('password');
    elemento.type = "password";
}






