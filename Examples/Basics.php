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
        $user = $login_service->getUser();
        echo "Hi, you were successfully logged in:";
        echo '<pre>';
        var_dump($user);
    } else {
        echo "Login failed: ".$login_service->getLastError();
    }
} else {
    // Display login form
    ?>
    <form method="POST">
        Username:<br/>
        <input type="text" name="username"/><br/>
        Password:<br/>
        <input type="password" name="password"/><br/>
        <label><input type="checkbox" name="remember_me" value="on"/> Remember me</label>
        <input type="submit" value="login"/>
    </form>
    <?php
}