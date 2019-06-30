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
    password : '!Qwer4321',  //비밀번호는 알아서! 
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

//회원가입
app.post('/signup', (req,res)=>{
    console.log('signup post ok!');
    const body=req.body;  //body는 {} front 쪽에서 header에 content-type 지정을 해주어야 정상적으로 데이터 찍힌다.
    const user_id = body.user_id;
    const user_pw = body.user_pw;
    const user_name = body.user_name;
    const user_profile = body.profile;
    
    //암호화
    const key = crypto.pbkdf2Sync(user_pw, 'salt', 100000, 64, 'sha512').toString('hex');

    //escape 문법
    const sql ={user_id:user_id,user_pw:key, user_name:user_name,user_profile:user_profile};
    
    //id중복조회 후 없으면 삽입.
    const selectQuery = connection.query('select user_id from users where user_id=?',[user_id],(err,rows)=>{
        console.log(rows);
        if(rows.length == 0){
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
    });     
})

//로그인 (passport없이 구현)
app.post('/login',(req,res)=>{
    const body=req.body; 
    const user_id = body.user_id;
    const user_pw = body.user_pw;   
  
    //id중복조회 
        const selectQuery = connection.query('select user_id,user_pw from users where user_id=?',[user_id],(err,rows)=>{
            if(err) throw err;
            
            if(!rows[0]){  
                console.log("클라이언트 전달")
                return res.json({message : 'not exist id',status: 500});
            }

             const key = crypto.pbkdf2Sync(user_pw, 'salt', 100000, 64, 'sha512').toString('hex');
             if(key === rows[0].user_pw){
                 return res.json({message : 'login success!', status : 200});
             }else{
                 return res.json({message : 'login failed!', status : 500});
             }       
        });    
})


//트윗


app.listen(9000,()=>{
    console.log("서버가 열렸습니다 : 연결완료 9000포트!");
})



