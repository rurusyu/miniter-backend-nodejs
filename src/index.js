const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mysql = require('mysql');
const cors = require('cors');  //npm install cors
const crypto = require('crypto'); //암호화 내장모듈


const connection = mysql.createConnection({
    host : 'localhost',
    port : 3306,
    user : 'root',
    password : '!Rmfltmeh1',
    database : 'miniter_db',
})

//mysql 연결하기.
connection.connect();

//cors제거용.
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended:true}));

app.get('/signup', (req,res)=>{
    res.json({message : 'This is CORS-enabled for all origins!'});
})

app.post('/signup', (req,res)=>{
    console.log('signup post ok!');
    const body=req.body;  //body는 {} front 쪽에서 header에 content-type 지정을 해주어야 정상적으로 데이터 찍힌다.
    const user_id = body.user_id;
    const user_pw = body.user_pw;
    const user_name = body.user_name;
    const user_profile = body.profile;
    
    //암호화
    const key = crypto.pbkdf2Sync(user_pw, 'salt', 100000, 64, 'sha512');

    //escape 문법
    const sql ={user_id:user_id,user_pw:key, user_name:user_name,user_profile:user_profile};
    
    //id중복조회 후 없으면 삽입.
    const selectQuery = connection.query('select user_id from users where user_id=?',[user_id],(err,rows)=>{
        console.log(rows);
        try{
            if(rows.length === 0){
                const query = connection.query('insert into users set ?',sql,(err,rows)=>{
                    if(err){
                        throw err;
                    }else{
                        res.json({message : '200 OK'})   //프론트로 뿌려줌.
                    }
                });
            }else{
                res.json({message : '400 Bad Request'}); 
            }
        }catch(err){
            throw err;
        }
    });    
})

app.listen(9000,()=>{
    console.log("서버가 열렸습니다 : 연결완료 9000포트!");
})



