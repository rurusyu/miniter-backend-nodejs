const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mysql = require('mysql');
const cors = require('cors');  //npm install cors
const crypto = require('crypto'); //암호화 내장모듈
//passport 모듈 설치
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const flash = require('connect-flash');

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

//passport설정은 라우터 전에 셋팅을 해준다.
app.use(session({
    secret : 'keyboard cat', //세션암호화에 대한 키값설정. 아무거나 쓰면됨.
    resave : false,
    saveUninitialized : true,
}))
//셋팅완료.
app.use(passport.initialize()); //passport 초기화
app.use(passport.session());
app.use(flash());

//1.회원가입
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

//serialize 처리 해주어야함.(세션에 넣어줘야함) 
passport.serializeUser(function(user, done){
    console.log("실행 3")
  console.log('passport session save : ', user)   //done에서 user_id로 넘겼으면 여기서도 done으로 받아야함.
  done(null, user);
});

//요청시 세션값 뽑아서 페이지 전달 , 인증된 이후(로그인) 여기에 저장된 값으로 DB에서 사용자와 일치하는 값을 가져와서 화면에 뿌려준다.
passport.deserializeUser(function(user, done){
  console.log("실행 4")
  console.log('passport session get id : ', user)
  done(null, user);
})


//strategy를 등록, 이걸 사용하기 위해서 등록한 거임.
//인증처리는 실제여기서. db 조회 로직 여기다가 작성하고, 밑에 post로 들어오면 여기서 체크하는 것임.
passport.use('local-login', new LocalStrategy({
    usernameField : 'user_id',
    passwordField : 'user_pw',
    passReqToCallback : true
    }, function(req, user_id, user_pw, done){
        console.log("작동순서1");
       //로그인 인증처리
      const key = crypto.pbkdf2Sync(user_pw, 'salt', 100000, 64, 'sha512').toString('hex');
      const query = connection.query('select user_id, user_pw,user_profile from users where user_id=?', [user_id], function(err,rows){
        if(err) return done(err);
        if(rows.length && key === rows[0].user_pw){       
            return done(null, {message : 'success login!!', status:200,'user_id' : rows[0].user_id, 'user_profile': rows[0].user_profile}); //세션에 담을 정보. 여기에서 id 값으로 넘겨야 serialize에서 id로 받을 수있음.
        }else if(rows.length && key !== rows[0].user_pw){
            return done(null, false, {message : 'login failed!', status : 500}); 
        }else{
            return done(null, false, {message : 'not exist id' , status : 500});            
        }
      })    
    } 
));


//1.로그인 (passport로 구현)
app.post('/login',(req,res, next)=>{
    passport.authenticate('local-login', function(err, user, info){
        console.log("작동순서2");
        if(err) res.status(500).json(err);
        if(!user) {
            return res.status(401).json(info.message)
        }
       // req.login을 이용해서 serialize 기능이 자연스럽게 이어지도록 되어있음. serialize 다음에 실행됨.
       req.logIn(user, function(err){
           if(err) {return next(err);}
           console.log("user", user)
           return res.json(user);  //front로 정보보냄
       });
    })(req, res, next); //authenticate 반환 메서드에 이 인자를 넣어서 처리해야함. 
});


//트윗
app.get('/tweet', (req,res)=>{
    console.log("회원정보", req.user);
    res.send('ddd')
})

app.listen(7300,()=>{
    console.log("서버가 열렸습니다 : 연결완료 7300포트!");
})


