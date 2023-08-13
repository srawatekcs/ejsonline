const express = require('express')
const app = express()
const PORT = process.env.PORT || 3000
const fs = require('fs')
const bcrypt = require('bcrypt')
const cookie = require('cookie-parser')
const jwt = require('jsonwebtoken')



app.use(cookie())
app.use(express.json())


app.get("/signup", (req,res)=>{
    res.sendFile(__dirname + "/signup.html")
})



app.post("/signup", (req,res)=>{

 let email = req.body.email
 let password = req.body.password


 fs.readFile("./users/" + email, async (err, data)=>{

  if(err)
  {




   let hashedPassword = await bcrypt.hash(password, 10)

    fs.writeFile("./users/"+ email, hashedPassword, (err)=>{
        if(err)
        {
            res.send({message: err.message})
        }
        else
        {
            res.send({message: "Account Created"})
        }

    })



  }
  else
  {
       res.send({message: "Account already exist"})
  }










 })



})


app.get("/login", (req,res)=>{
    res.sendFile(__dirname + "/login.html")
})

app.post("/login", async (req,res)=>{
    let email = req.body.email
    let password = req.body.password



    fs.readFile("./users/"+ email, async (err,data)=>{
       if(err)
       {
        console.log(err)
        res.send({message: "No account with this email id"})
       }
       else
       {
          let hashedPassword = data.toString()
          let isTrue = await bcrypt.compare(password, hashedPassword);

          if(isTrue)
          {
               

          let payload = {email}
          let token = jwt.sign(payload, "Server_side_password")
          console.log(token)
           res.cookie("login", token)
           res.send({message:"login successful"})
           


          }
          else
          {
            res.send({message: "Password incorrect"})
          }
       }


    })


})



function checker(req,res,next)
{

try{   if(req.cookies.login){
    let login = req.cookies.login
    let payload = jwt.verify(login, "Server_side_password")
    console.log("New request coming from:", payload.email)
    next()
   }
} catch(err){
    res.send("Login error or token tampered")
}





}


app.get("/logout", (req,res)=>{
    res.clearCookie("login")
    res.send("Logout successful")
})


app.get("/protected", checker, (req,res)=>{
    res.send("Ultra Secret Data ")
})







app.listen(PORT, (err)=>{
    if(err)
    console.log(err)
    else
    console.log("Server is running on PORT:", PORT)
})


