<?php
/*
A simple example.
A page that shows whether it is secure, and offers a way to upgrade to secure login
*/

$config = [
    "host" => "",
    "user" => "",
    "database" => "",
    "password" => ""
];

// Initialize mysql database connection
$db = new \PDO("mysql:host=".$config['host'].";dbname=".$config['database'], $config['user'], $config['password'], [
    \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
    \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
]);

// Load third party libraries
require_once __DIR__ . '/../vendor/autoload.php';

// Initialize login service
$login_service = new \Avokicchi\LoginManager\LoginService($db,"_test");
$login_service->init("/");

// Customize database fields (optional)
$login_service->setUserTableName("user");//it defaults to "users", here we override it.
$login_service->setUserField("username","email");

// If you sent in a form...
if($_SERVER['REQUEST_METHOD']=="POST"){
    $remember_me = isset($_POST['remember_me']) && $_POST['remember_me']=="on";
    if($login_service->login($_POST['username'],$_POST['password'],$remember_me)){
        echo "You were successfully logged in.";
    } else {
        echo "Login failed: ".$login_service->getLastError();
    }
}

if($login_service->isLoggedIn()){
    $user = $login_service->getUser();
    echo "Logged in as ".$user['email'];
    echo '<hr/>';
    // Check if login is through a session (secure) or a cookie (not secure)

    if($login_service->isLoginSecure()){
        echo "You are on this page through a direct login, not a cookie extension. This page is secure.";
    } else {
        echo "You are on this page through a cookie. This page is NOT secure. Feel free to refresh your login below: ";
    }
} 

if(!$login_service->isLoggedIn() || !$login_service->isLoginSecure()){
    // Display login form
    ?>
    <form method="POST">
        Username:<br/>
        <input type="text" name="username"/><br/>
        Password:<br/>
        <input type="password" name="password"/><br/>
        <label><input type="checkbox" checked name="remember_me" value="on"/> Remember me</label>
        <input type="submit" value="login"/>
    </form>
    <?php
}