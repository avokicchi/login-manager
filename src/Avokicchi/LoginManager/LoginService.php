<?php

namespace Avokicchi\LoginManager;

/**
 * Class LoginService
 *
 * Extended login module with cookie session restore
 */
class LoginService {

    private $_template;
    private $_cookieName = null;
    private $_cookiePath = null;
    private $_urlPath="/";
    private $_cookeLifetime=1800;
    private $_hashSecret="any_secret_key";
    private $_pdo=null;

    private $_dbTable = "users";

    private $_dbFields = [
        "id" => "id",
        "username" => "username",
        "password" => "password"
    ];

    /**
    * Instantiates the Login class.
    * 
    * @param object $pdo            Database connection, \PDO object.
    * @param string $cookieName     name of your cookie.
    *
    * @return void
    */
    function __construct($pdo,$cookieName="_youridx") {
        $this->_pdo=$pdo;
        $this->_cookiePath = __DIR__.DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."..".DIRECTORY_SEPARATOR."cache".DIRECTORY_SEPARATOR."sessions".DIRECTORY_SEPARATOR;//outside your publicly shared documentroot.
        $this->_cookieName = $cookieName;
        $this->_cookiePath=str_replace("\\", "/", $this->_cookiePath);
        @mkdir($this->_cookiePath,0777,true);
    }

    /**
    * Allows overriding default database table name.
    *
    * @param string $tableName  New db table name
    * 
    * @return void
    */
    public function setUserTableName($tableName) {
        $tableName = preg_replace("/[^A-Za-z0-9]/", '', $tableName);
        $this->_dbTable=$tableName;
    }

    /**
    * Allows overriding default database field names if yours are different (email instead of username, pk instead of id, whatever)
    *
    * @param string $field  id|username|password
    * @param string $value  New db column name
    * 
    * @return bool
    */
    public function setUserField($field,$value) {
        $value = preg_replace("/[^A-Za-z0-9]/", '', $value);
        if(array_key_exists($field,$this->_dbFields)) {
            $this->_dbFields[$field]=$value;
            return true;
        } else {
            return false;
        }
    }

    /**
    * Function for extra secure pages. Determines whether your login is the result of a login, 
    * or by an extension of lifetime by a cookie, which is inherently less secure. 
    * You can use this to ask for an extra login action on an extra secure page.
    * 
    * @return bool
    */
    public function isLoginSecure() {
        return $this->isLoggedIn() && isset($_SESSION['secure']) && $_SESSION['secure'];
    }

    /**
    * Initializes login system, starts session, restore login from cookie, etc
    *
    * @param string $path  The ability to set a sub path where cookies apply to, like /account
    * 
    * @return void
    */
    public function init($path="/") {
        $this->_urlPath=$path;
        $secure = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
        // Start the session
        ini_set('session.cookie_lifetime', $this->_cookeLifetime);
        session_set_cookie_params([
            'lifetime' => $this->_cookeLifetime,
            'path' => $path==null ? '/' : $path,
            'secure' => $secure,
            'httponly' => $secure
        ]);
        session_start(['cookie_secure' => $secure,'cookie_httponly' => $secure]);
        // Check if user is already logged in using a cookie
        if (isset($_COOKIE[$this->_cookieName]) && !$this->isLoggedIn()) {
            // Get the hash from the cookie
            $cookieHash = $_COOKIE[$this->_cookieName];
            $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
            $lastActivity = $this->getLastActivityFromCookie($cookieHash);
            $weekAgo = time() - (7 * 24 * 60 * 60);
            if ($lastActivity < $weekAgo) {
                $this->logout();
            } else {
                // Retrieve the userId from the server file
                $userId = $this->getUserIDFromCookie($cookieHash);
                $this->clearCookie($cookieHash);
                // If userId exists, log the user in programmatically
                if ($userId) {
                    $this->programmaticLogin($userId, true);
                }
                $_SESSION['secure'] = false;
            }

        }
        if(!$this->isLoggedIn()) {
            session_regenerate_id();//regenerate session cookie with correct expiration. seems to work
        }
    }

    /**
    * Sets the current error produced by verify()
    *
    * @param string       The error
    * 
    * @return void
    */
    private function setLastError($err) {
        $_SESSION['last_login_error']=$err;
    }

    /**
    * Gets the last error produced by verify()
    *
    * @return string       The error
    */
    public function getLastError() {
        return $_SESSION['last_login_error'];
    }

    /**
    * Generates a hash to store the cookie with
    *
    * @param int $userId   The user ID
    * 
    * @return string       The hash
    */
    private function generateCookieHash($userId) {
        $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $token = '';
        $max = mb_strlen($keyspace, '8bit') - 1;
        for ($i = 0; $i < 16; ++$i) {
            $token .= $keyspace[random_int(0, $max)];
        }
        return hash('sha256', $userId . $token . $this->_hashSecret);
    }

    /**
    * Retrieves the user's ID from the cookie
    *
    * @param string $cookieHash   The hash for the the cookie filename
    * 
    * @return int|bool            The user ID or false if the hash is invalid or the file doesn't exist
    */
    private function getUserIDFromCookie($cookieHash) {
        $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
        $cookieFile = $this->_cookiePath. $cookieHash . ".txt"; 
        if (file_exists($cookieFile)) {
            $bits = file_get_contents($cookieFile);
            $bits = explode("|",$bits);
            return intval($bits[0]);
        } else {
            return false;
        }
    }

    /**
    * Retrieves the user's last activity timestamp from the cookie
    *
    * @param string $cookieHash     The hash for the the cookie filename
    * 
    * @return bool                  Whether something was removed or not.
    */
    private function clearCookie($cookieHash) {
        $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
        $cookieFile = $this->_cookiePath. $cookieHash . ".txt"; 
        if (file_exists($cookieFile)) {
            @unlink($cookieFile);
            return true;
        } else {
            return false;
        }
    }

    /**
     * Retrieves the user's last activity timestamp from the cookie
     *
     * @param string $cookieHash   The hash for the the cookie filename
     * 
     * @return int|bool            The last activity timestamp or false if the hash is invalid or the file doesn't exist
     */
    private function getLastActivityFromCookie($cookieHash) {
        $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
        $cookieFile = $this->_cookiePath. $cookieHash . ".txt"; 
        if (file_exists($cookieFile)) {
            $bits = file_get_contents($cookieFile);
            $bits = explode("|",$bits);
            return intval($bits[1]);
        } else {
            return false;
        }
    }

    /**
     * Saves the user's id and current time in a file on the server with the hash as the file name.
     *
     * @param int $userId           The user ID
     * @param string $cookieHash    The cookie hash
     * 
     * @return void
     */
    private function saveUserIDInCookieFile($userId,$cookieHash) {
        $cookieHash = preg_replace("/[^A-Za-z0-9]/", '', $cookieHash);
        $cookieFile = $this->_cookiePath. $cookieHash . ".txt"; 
        file_put_contents($cookieFile, $userId. "|" . time());
    }

    /**
    * Verifies a user's login details and returns success
    * 
    * @param string $username  The username
    * @param string $password  The password
    * 
    * @return bool
    */
    public function verify($username, $password) {
        // Query database for user with matching username
        $stmt = $this->_pdo->prepare("SELECT * FROM ".$this->_dbTable." WHERE ".$this->_dbFields["username"]." = :username");
        $stmt->execute([":username" => $username]);
        $user = $stmt->fetch(\PDO::FETCH_ASSOC);
        // Check if user was found
        if (!empty($user)) {
            // Verify password
            if (password_verify($password, $user[$this->_dbFields["password"]])) {
                // Password is correct
                return true;
            } else {
                // Password is incorrect
                $this->setLastError("Login details incorrect.");
                return false;
            }
        } else {
            // User not found
            $this->setLastError("User not found.");
            return false;
        }
    }

    /**
    * Gets a user's ID from their username.
    * 
    * @param string $username  The username
    * 
    * @return integer
    */
    private function getUserIdByUsername($username) {
        // Query the database for the user ID
        $stmt = $this->_pdo->prepare("SELECT * FROM ".$this->_dbTable." WHERE ".$this->_dbFields["username"]." = :username");
        $stmt->execute([":username" => $username]);
        $user = $stmt->fetch(\PDO::FETCH_ASSOC);
        // If the user was found, return the user ID
        if ($user) {
            return $user[$this->_dbFields["id"]];
        }
        // If the user was not found, return null
        return null;
    }

    /**
    * Verifies a passed username and password, and logs a user in, either with or without cookie login extension.
    * 
    * @param string $username   The username
    * @param string $password   The password
    * @param bool $rememberMe   Extend login lifetime using cookies.
    * 
    * @return bool
    */
    public function login($username, $password, $rememberMe) {
        // Verify the username and password
        if (!$this->verify($username, $password)) {
            return false;
        }
        // Get the user ID
        $user_id = $this->getUserIdByUsername($username);
        $this->programmaticLogin($user_id,$rememberMe);
        $_SESSION['secure'] = true;
        return true;
    }

    /**
    * Performs the actions that log the user in. Can also be used to programatically force a login, for instance if you implement security challenges with 2fa.
    * 
    * @param integer    $userId         The user's ID.
    * @param bool       $rememberMe     Extend login lifetime using cookies.
    * 
    * @return void
    */
    public function programmaticLogin($userId, $rememberMe) {
        $userId=(int)$userId;
        // Set session variables
        $_SESSION['user_id'] = $userId;
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
        // Set cookie
        if ($rememberMe) {
            $cookieHash = $this->generateCookieHash($userId);
            $this->saveUserIDInCookieFile($userId,$cookieHash);
            setcookie($this->_cookieName, $cookieHash, time() + 60 * 60 * 24 * 30, $this->_urlPath);
        }
    }

    /**
    * Logs the user out.
    * 
    * @return void
    */
    public function logout() {
        // Clear session data
        $_SESSION = [];
        // Delete session cookie
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], 
            $params["domain"],
            $params["secure"], 
            $params["httponly"]
        );
        $cookieHash = is_array($_COOKIE) && array_key_exists($this->_cookieName,$_COOKIE) ? $_COOKIE[$this->_cookieName] :  null;
        if(!empty($cookieHash)) {
            $this->clearCookie($cookieHash);
        }
        // Delete remember me cookie
        setcookie($this->_cookieName, '', time() - 3600,$this->_urlPath);
        // Destroy session
        session_destroy();
    }

    /**
    * Returns the user object associated with the login session.
    * 
    * @return mixed
    */
    public function getUser() {
        // Check if user is logged in
        if ($this->isLoggedIn()) {
            // Get user id from session
            $userId = $_SESSION['user_id'];
            // Query database for user details
            $stmt = $this->_pdo->prepare("SELECT * FROM ".$this->_dbTable." WHERE ".$this->_dbFields["id"]." = :user_id");
            $stmt->execute([":user_id" => $userId]);
            $user = $stmt->fetch(\PDO::FETCH_ASSOC);
            // Return user details as associative array
            return $user;
        } else {
            // User is not logged in so return null
            return null;
        }
    }

    /**
    * Creates a user
    * 
    * @param string $username   The username
    * @param string $password   The password
    * 
    * @return integer|bool          Successful or not, if successful, a user id.
    */
    public function createUser($username,$password) {
        $stmt = $this->_pdo->prepare("INSERT INTO ".$this->_dbTable." (".$this->_dbFields["username"].",".$this->_dbFields["password"].") VALUES (:username,:password)");
        try {
            $stmt->execute([":username" => $username, ":password" => password_hash($password, PASSWORD_DEFAULT)]);
            return $this->_pdo->lastInsertId();
        } catch(\Throwable $e){
            return false;
        }
    }

    /**
    * Checks whether the user is logged in, and performs some security checks.
    * 
    * @return bool
    */
    public function isLoggedIn() {
        // Check if user ID is set in session
        if (isset($_SESSION['user_id']) && isset($_SESSION['ip'])) {
            // Verify user agent/ip
            if ($_SESSION['user_agent'] === $_SERVER['HTTP_USER_AGENT'] && $_SESSION['ip']===$_SERVER['REMOTE_ADDR']) {
                // User is logged in
                return true;
            } else {
                // User agent mismatch, possible session hijacking attempt
                $this->logout();
            }
        }
        // User is not logged in
        return false;
    }

}