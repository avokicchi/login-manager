Drop-in PHP login module that's database agnostic, doesn't require any libraries, and supports remember-me functionality. 

NOT ANYWHERE NEAR PRODUCTION READY, DO NOT USE IN YOUR PROJECTS.

Installation is simple

composer require avokicchi/login-manager

features:
- regular login
- drop in any project, database agnostic.

I will never extend this library with password recovery, email validation, or two-factor authentication as that goes way beyond the scope of this and would require including libraries and defeats the point of this, which is to provide a simple login system for simple projects. You can always build on top of it to provide all that yourself. I would at the moment probably recommend phpgangsta/googleauthenticator for two factor auth, and mandrill/mailchimp or mailgun for your email needs.

requirements:
- php 7.2+
- database that works with pdo

Hope this is useful to anyone. ~ Avo

NOT ANYWHERE NEAR PRODUCTION READY, DO NOT USE IN YOUR PROJECTS.

Crappy usage example with slim framework dependency injection:

in your index.php/web accessible index page, etc:

	require_once 'vendor/autoload.php';
	$app->container->singleton(
	    'login',
	    function ($container) use ($pdo) {
	        global $config;
	        return new \Avokicchi\LoginManager\LoginService($pdo,"_someidx");
	    }
	);
	$app->container['login']->init("/");
	$app->container['login']->setUserTableName("user");
	$app->container['login']->setUserField("username","email");

logout function:

    public function logout()
    {
        $app = \Slim\Slim::getInstance();
        $app->container['login']->logout();
        return $this->redirect("/");
    }

login function:

    public function login()
    {     
        $app = \Slim\Slim::getInstance();
        if($_SERVER['REQUEST_METHOD']=="POST"){
            if(!$app->container['login']->login($_POST['username'],$_POST['password'],true)){
                die($app->container['login']->getLastError());
            }
            return $this->redirect("/");
        } else {
            return $app->render("login.html", []);/show a login form with a username and password field that posts the form to this exact page with method=post
        }
    }