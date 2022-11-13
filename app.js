//import pour generer notre token
const jwt = require('jsonwebtoken')
require('dotenv').config();
//import de express pour faire notre router
const express = require('express');

const app = express();
//qui explique qu'on va utiliser du json pour la recupération de paramètre
app.use(express.json());
//qui va nous servire a encoder le contenu
app.use(express.urlencoded({ extended: true}));


const user = {
    id: 58,
    name: 'marc Fantino',
    email:'marc-fantino-blueline-dev@hotmail.com',
    admin: true,
};

function generateAccessToken (user){
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1800s'});// le token expire apres 30 minutes
}
function generateRefreshToken (user){
    return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, {expiresIn: '1y'}); // il est refresh pendant 1 an
}



// on créer notre premiere route
// requete envoyé et reponse attendu
app.post('/api/login', (req, res) => {
    //on vérifie le l'email et le mdp qui recupere de la requete
  
    if(req.body.email !== user.email) {
    // retour le code 401 pour dire qu'on est pas autorisé
    res.status(401).send('Informations d’identification non valides');
    return ;
    }
    if(req.body.password !== 'gateaux') {
        // retour le code 401 pour dire qu'on est pas autorisé
        res.status(401).send('Informations d’identification non valides');
        return ;
        }
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user)
    res.send({
        accessToken,
        refreshToken,
    });
});
// on crée une route pour le refresh du token
app.post('/api/refreshToken', (req, res) =>{
    //on récupere le jwt dans le header
    const authHeader = req.headers['authorization'];
    // on check qu'il est pas null
    const token = authHeader && authHeader.split(' ')[1]; // l'index 0 c'est Bearer(la clef) et l'index 1 le token
    if (!token){
        return res.sendStatus(401);
    }
    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if(err) {
        return res.sendStatus(401);
        }
        //on check en bdd que le user a toujours les droits et qu'il existe toujours
        //
        delete user.iat;
        // date d'expiration
        delete user.exp;
        const refreshToken = generateAccessToken(user);
        res.send({
            accessToken: refreshToken,
        });
    });
});
//oncréer un middleware qui va créer des routes authentifié 
function authenticateToken (req, res, next){
    //on récupere le jwt dans le header
    const authHeader = req.headers['authorization'];
    // on check qu'il est pas null
    const token = authHeader && authHeader.split(' ')[1]; // l'index 0 c'est Bearer(la clef) et l'index 1 le token
    if(!token){
        //on vérifie qu'il est pas null
        return res.sendStatus(401);
    }
    // on passe la clef secrete en paramètre pour le déchiffrer 
    // on passe une function qui va etre appeler si il y a une erreur
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) =>{
    // si il y as une erreur
    if (err){
    // on returne si il y a une erreur
    return res.sendStatus(401);
    }
    // sinon dans request.user
    // nos routes authentifier recupere le user
    req.user = user;
    // on appelle next pour appeler la logique du code de la route API qui necessite cette authentification 
    next()
    });
};
//on créer une route avec la méthode get qui recupere le middleware
app.get('/api/me', authenticateToken, (req, res) =>{
    res.send(req.user);
})
// on ecoute sur le port 3000
app.listen(3000, () => {console.log('serveur lancé sur le port 3000')});