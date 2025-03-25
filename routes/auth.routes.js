const router = require("express").Router();

const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

const { verifyToken, verifyAdminRole } = require("../middlewares/auth.middlewares")

const User = require("../models/User.model")

// POST "/api/auth/signup" => Ruta para crear el documento de usuario
router.post("/signup", async (req, res, next) => {

  // Validaciones de Servidor

  const { email, username, password } = req.body

  // verificar que los valores existan
  if (!email || !username || !password) {
    res.status(400).json({errorMessage: "Todos los campos son obligatorios"})
    return // detener la ejecucion de la funcion
  }

  // que el nombre de usuario tenga minimo 3 caracteres: TAREA
  // el usuario no incluya caracteres especiales: TAREA
  
  // el password sea fuerte
  const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[a-zA-Z]).{8,}$/gm
  if (passwordRegex.test(password) === false) {
    res.status(400).json({errorMessage: "Contraseña no es suficiente fuerte. Require al menos una mayuscula, una minuscula, un numero y 8 caracteres."})
    return // detener la ejecucion de la funcion
  }

  // el email tenga el formato correcto. TAREA

  try {

    // que el email no se repita
    const foundUser = await User.findOne({ email: email })
    // console.log(foundUser)
    if (foundUser !== null) {
      res.status(400).json({errorMessage: "Ya existe un usuario con ese email"})
      return // detener la ejecucion de la funcion
    }

    const hashPassword = await bcrypt.hash(password, 12)
    
    await User.create({
      email: email,
      username: username,
      password: hashPassword
    })

    res.sendStatus(201)

  } catch (error) {
    next(error)
  }

})

// POST "/api/auth/login" => Ruta para validar credenciales del usuario y crear el token
router.post("/login", async (req, res, next) => {

  const { email, password } = req.body

  // que los campos existan
  if (!email || !password) {
    res.status(400).json({errorMessage: "Todos los campos son obligatorios"})
    return
  }
  
  // que el email tenga el formato correcto. TAREA
  
  // que pueda hacer login con el email o con el usuario (si fuese unico). OPCIONAL
  
  try {
    
    // que el usuario exista con ese email
    const foundUser = await User.findOne({email: email})
    if (foundUser === null) {
      res.status(400).json({errorMessage: "Usuario no encontrado con ese email"})
      return
    }
  
    // que la contraseña corresponda con la almacenada
    const isPasswordCorrect = await bcrypt.compare(password, foundUser.password)
    if (isPasswordCorrect === false) {
      res.status(400).json({errorMessage: "Contraseña no valida"})
      return
    }
    
    // HEMOS AUTENTICADO AL USUARIO
    // creamos el token y lo enviamos al cliente

    const payload = {
      _id: foundUser._id,
      email: foundUser.email,
      role: foundUser.role
    } // el payload es la información unica del usuario que lo identifica y que estará dentro del token.

    const authToken = jwt.sign(payload, process.env.TOKEN_SECRET, { algorithm: "HS256", expiresIn: "7d" })

    res.status(200).json({authToken: authToken})

  } catch (error) {
    next(error)
  }
  
})

// GET "/api/auth/verify" => verificar validez del token e indicar a toda la aplicacions que el usuario fue autenticado
router.get("/verify", verifyToken, (req, res) => {

  // tenemos que validar el token. Lo validamos con el middlere verifyToken

  //! CON EL REQ.PAYLOAD EL SERVIDOR SABE QUIEN ES EL USUARIO QUE ESTÁ HACIENDO LAS ACCIONES.
  console.log(req.payload)


  //! indicar al FE que el usuario fue validado recientemente Y EL FRONTED RECIBE INFO DE QUIEN ES ESE USUARIO
  res.status(200).json({payload: req.payload}) 

} )


// EJEMPLO DE RUTA PRIVADA SOLO ACCESIBLE PARA USUARIOS LOGEADOS
router.post("/crear-una-banana", verifyToken, (req, res) => {
  
  // Banana.create(...)

  console.log(req.payload._id) // Esto me dice el id del usuario que está creando la banana
  res.status(201).json("has creado una banana")
})

// EJEMPLO DE RUTA PRIVADA SOLO ACCESIBLE PARA USUARIOS LOGEADOS Y DE TIPO ADMIN
router.delete("/borrar-una-banana-solo-admin", verifyToken, verifyAdminRole, (req, res) => {
  
  // Banana.delete(...)

  console.log(req.payload._id) // Esto me dice el id del usuario que está creando la banana
  res.status(201).json("has borrado una banana porque eres un admin")
})


module.exports = router