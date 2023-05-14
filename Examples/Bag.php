<?php
/*
A simple example.
A page that shows off the key/value storage feature.
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
    // Process login
    if($_POST['action']=="login"){
        $remember_me = isset($_POST['remember_me']) && $_POST['remember_me']=="on";
        if($login_service->login($_POST['username'],$_POST['password'],$remember_me)){
            echo "Hi, you were successfully logged in:";
        } else {
            echo "Login failed: ".$login_service->getLastError();
        }
    // Process login value store
    } else if($_POST['action']=="store"){
        $login_service->set("yourkey",$_POST['value']);
    }
} 

if($login_service->isLoggedIn()){
    $user = $login_service->getUser();
    echo "Logged in as ".$user['email'].". Store a value below:";
    $yourvalue = $login_service->get("yourkey");
    // Display key/value storage form
    ?>
    <hr/>
    <form method="POST">
        key:<br/>
        <input type="text" disabled readonly name="key" value="yourkey"/><br/>
        value:<br/>
        <input type="text" name="value"/><br/>
        <input type="hidden" name="action" value="store"/>
        <input type="submit" value="Save"/>
    </form>
    Previously saved value is: <?php echo $yourvalue; ?>
    <?php
    echo '<hr/>';
} else {
    // Display login form
    ?>
    <form method="POST">
        Username:<br/>
        <input type="text" name="username"/><br/>
        Password:<br/>
        <input type="password" name="password"/><br/>
        <input type="hidden" name="action" value="login"/>
        <label><input type="checkbox" name="remember_me" value="on"/> Remember me</label>
        <input type="submit" value="login"/>
    </form>
    <?php
}