<?
$vink = @pg_connect('dbname=vink user=vink password=v4g4boon host=localhost');

if(!$vink)
{
  $error = 'Database connection failed';
}

if(array_key_exists('vink-user', $_POST) && array_key_exists('vink-secret', $_POST))
{
  if(array_key_exists('session', $_COOKIE))
    pg_query_params($vink, 'DELETE FROM vink_sessions WHERE id = $1', array($_COOKIE['session']));

  $user_res = pg_query_params($vink, 'SELECT * FROM vink_users WHERE name = $1', array($_POST['vink-user']));

  if(!pg_num_rows($user_res))
  {
    require('403.php');

    exit;
  }

  $user_row = pg_fetch_array($user_res);

  if($user_row['secret'] != $_POST['vink-secret'])
  {
    require('403.php');

    exit;
  }

  $vink_userid = $user_row['id'];
  $vink_sessionid = sha1($vink_userid . uniqid() . time() . $vink_secret);
  setcookie('session', $vink_sessionid, time() + 3600 * 24 * 365, '/', $_SERVER['HTTP_HOST']);
  
  pg_query_params('INSERT INTO vink_sessions (id, user_id) VALUES ($1, $2)',
                  array($vink_sessionid, $vink_userid));
}
else if(array_key_exists('session', $_COOKIE))
{
  $session_res = pg_query_params($vink, 'SELECT user_id FROM vink_sessions WHERE id = $1', array($_COOKIE['session']));

  if(!pg_num_rows($session_res))
  {
    require('403.php');

    exit;
  }

  $session_row = pg_fetch_array($session_res);

  $vink_sessionid = $session_row['id'];
  $vink_userid = $session_row['user_id'];
}
else
{
  require('403.php');

  exit;
}


?>
