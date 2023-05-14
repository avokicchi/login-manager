<?php
/*
Most simple example possible.
A login form in a single script.
*/

$config = [
    "host" => "",
    "user" => "",
    "database" => "",
    "password" => ""
];

//initialize mysql database connection
$db = new \PDO("mysql:host=".$config['host'].";dbname=".$config['database'], $config['user'], $config['password'], [
    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
    \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
]);

//load third party libraries
require_once __DIR__ . '/../vendor/autoload.php';

$login_service = new \Avokicchi\LoginManager\LoginService($db,"_test");
$login_service->init("/");
$login_service->setUserTableName("user");//it defaults to "users", here we override it.
$login_service->setUserField("username","email");

if($_SERVER['REQUEST_METHOD']=="POST"){
    if($login_service->login($_POST['username'],$_POST['password'],true)){
        $user = $login_service->getUser();
        echo "Hi, you were successfully logged in:";
        echo '<pre>';
        var_dump($user);
    } else {
        echo "Login failed: ".$login_service->getLastError();
    }
} else {
    ?>
    <form method="POST">
        Username:<br/>
        <input type="text" name="username"/><br/>
        Password:<br/>
        <input type="password" name="password"/><br/>
        <input type="submit" value="login"/>
    </form>
    <?php
}