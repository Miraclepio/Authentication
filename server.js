const express = require('express')
const app = express()
const port = 2000
app.use(express.json())
const db = require('./config/db')
const router = require('./routers/schoolRouter')
app.use(router)


app.listen(port, ()=>{
    console.log(`app is listening to ${port}`) 
})  