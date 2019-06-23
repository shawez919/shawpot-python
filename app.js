const express = require('express'),
    bodyParser = require('body-parser'),
    app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');
app.use(express.static('public'));

var data = [];

app.get('/',(req,res) => {
    res.render('home');
});

app.get('/data',(req,res) => {
    res.render('report',{data: data});
});

app.post('/intruder',(req,res) => {
    console.log(req.body);
    data.push(req.body);

    res.sendStatus(200);
});

app.listen('8080',()=> {
    console.log('Port started at 8080');
});