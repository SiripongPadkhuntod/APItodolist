var express = require('express')
var cors = require('cors')
var app = express()
var bodyParser = require('body-parser')
// create application/json parser
var jsonParser = bodyParser.json()
const bcrypt = require('bcrypt');
const saltRounds = 10;

var jwt = require('jsonwebtoken');
var secret = 'ToDoLsit-2023';



app.use(cors())

require('dotenv').config()
const mysql = require('mysql2')
const connection = mysql.createConnection(process.env.DATABASE_URL)
console.log('Connected to PlanetScale!')
//connection.end() 

// const mysql = require('mysql2');
// // create the connection to database
// const connection = mysql.createConnection({
//     host: 'localhost',
//     user: 'root',
//     database: 'todolist'
//   });

app.post('/register', jsonParser , function (req, res, next) {
    bcrypt.hash(req.body.Password, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        connection.execute(
          'INSERT INTO userdata (Username,Password,Fname,Lname,Phone,Email) VALUES (?,?,?,?,?,?)',
          [req.body.Username, hash, req.body.FName, req.body.LName, req.body.Phone, req.body.Email],
          function(err, results, fields) {
            if (err){
              res.json({status:"error",message: err})
              return
            }
            res.json({status:"ok"})
          }
        );
    });
})

app.post('/login', jsonParser , function (req, res, next) {
  connection.execute(
    'SELECT * FROM userdata WHERE Username = ?',
    [req.body.Username],
    function(err, results, fields) {
      if (err){
        res.json({status:"error",message: err})
        return
      }
      if(results.length == 0){
        res.json({status:"error",message: "Username not found"})
        return
      }
      bcrypt.compare(req.body.Password, results[0].Password, function(err, isLogin) {
        if(isLogin){
          //create token and add user id to token
          var token = jwt.sign({ Email: results[0].Email ,User: results[0].Username }, secret,{ expiresIn: "1h"}); //add user id to token
          res.cookie('token', token, { httpOnly: true });
          res.json({status:"ok", message: "Login success",token:token})
        }else{
          res.json({status:"error",message: "Password incorrect"})
        }
      });
    }
  );
})

app.post('/authen', jsonParser , function (req, res, next) {
  try {
    const token = req.headers['authorization'].split(' ')[1];
    var decoded = jwt.verify(token, secret);
    res.json({status:"ok",message: "Token is valid",decoded:decoded})
  } catch(err) {
    res.json({status:"error",message: "Token is invalid"})
  }
  
})

app.post('/logout', jsonParser , function (req, res, next) {
  res.clearCookie('token');
  res.json({status:"ok",message: "Logout success"})
})


app.post('/addlist', jsonParser , function (req, res, next) {
  try {
    connection.execute(
      'INSERT INTO listdata (ListName,ListDetail,ListCreateTime,ListTimeOut,ListCheck,UserID) VALUES (?,?,?,?,?,?)',
      [req.body.ListName, req.body.ListDetail, req.body.ListCreateTime, req.body.ListTimeOut, req.body.ListCheck, req.body.UserID],
      function(err, results, fields) {
        if (err){
          res.json({status:"error",message: err})
          return
        }
        res.json({status:"ok"})
      }
    );
  } catch(err) {
    res.json({status:"error",message: err})
  }
})

app.post('/getlist', jsonParser , function (req, res, next) {
  try {
    connection.execute(
      'SELECT * FROM listdata WHERE UserID = ?',
      [req.body.UserID],
      function(err, results, fields) {
        if (err){
          res.json({status:"error",message: err})
          return
        }
        res.json({status:"ok",data:results})
      }
    );
  } catch(err) {
    res.json({status:"error",message: err})
  }
})

// delete list
app.post('/deletelist', jsonParser , function (req, res, next) {
  try {
    connection.execute(
      'DELETE FROM listdata WHERE ListID = ?',
      [req.body.ListID],
      function(err, results, fields) {
        if (err){
          res.json({status:"error",message: err})
          return
        }
        res.json({status:"Delete success",data:results})
      }
    );
  } catch(err) {
    res.json({status:"error",message: err})
  }
})

// update list status check
app.post('/updatelist', jsonParser , function (req, res, next) {
  try {
    connection.execute(
      'UPDATE listdata SET ListCheck = 1 WHERE ListID = ?',
      [req.body.ListID],
      function(err, results, fields) {
        if (err){
          res.json({status:"error",message: err})
          return
        }
        res.json({status:"Update success",data:results})
      }
    );
  } catch(err) {
    res.json({status:"error",message: err})
  }
})


app.listen(3333, function () {
  console.log('CORS-enabled web server listening on port 3333')
})

