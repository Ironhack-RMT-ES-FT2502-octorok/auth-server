const jwt = require("jsonwebtoken")

function verifyToken(req, res, next) {

  console.log(req.headers)

  try {
   
    const token = req.headers.authorization.split(" ")[1] // extraer el token del header

    const payload = jwt.verify(token, process.env.TOKEN_SECRET)
    //1. valida que el token sea correcto
    //2. nos devuelve el payload (la info del dueño de ese token)
    //3. causa un error si el token no es valido

    req.payload = payload // recojer el payload del token y pasarlo a la ruta

    next() // continua con la proxima ruta
  } catch (error) {
    
    // si esta funcion entra en el catch, significa que el token no es valido.
    res.status(401).json({errorMessage: "token no valido o no existe"})

  }

}

function verifyAdminRole(req, res, next) {
  // este middleware SIEMPRE se pretende ejecutar despues de verifyToken
  if (req.payload.role === "admin") {
    next() // si eres admin, continue
  } else {
    res.status(401).json({errorMessage: "ruta solo para admins"})
  }

}

module.exports = {
  verifyToken,
  verifyAdminRole
}