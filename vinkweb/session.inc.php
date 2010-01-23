<?
require_once('config.inc.php');

$vink = pg_connect($vink_pg_connect_string);

if(!$vink)
{
  $error = 'Database connection failed';
}

if(array_key_exists('vink-user', $_POST) && array_key_exists('vink-secret', $_POST))
{
  if(array_key_exists('session', $_COOKIE))
    pg_query_params($vink, 'DELETE FROM sessions WHERE id = $1', array($_COOKIE['session']));

  $user_res = pg_query_params($vink, 'SELECT * FROM users WHERE username = $1', array($_POST['vink-user']));

  if(!pg_num_rows($user_res))
  {
    require('403.php');

    exit;
  }

  $user_row = pg_fetch_array($user_res);

  if($user_row['password'] != $_POST['vink-secret'])
  {
    require('403.php');

    exit;
  }

  $vink_userid = $user_row['seqid'];
  $vink_sessionid = sha1($vink_userid . uniqid() . time() . $vink_secret);
  setcookie('session', $vink_sessionid, time() + 3600 * 24 * 365, '/', $_SERVER['HTTP_HOST']);
  
  pg_query_params('INSERT INTO sessions (id, userid) VALUES ($1, $2)',
                  array($vink_sessionid, $vink_userid));
}
else if(array_key_exists('session', $_COOKIE))
{
  $session_res = pg_query_params($vink, 'SELECT userid FROM sessions WHERE id = $1', array($_COOKIE['session']));

  if(!pg_num_rows($session_res))
  {
    require('403.php');

    exit;
  }

  $session_row = pg_fetch_array($session_res);

  $vink_sessionid = $_COOKIE['session'];
  $vink_userid = $session_row['userid'];
}
else
{
  require('403.php');

  exit;
}


?>
