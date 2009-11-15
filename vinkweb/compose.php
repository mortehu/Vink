<?
require_once('config.inc.php');
require_once('session.inc.php');

if(array_key_exists('vink-message', $_POST))
{
  @pg_query($vink, 'BEGIN');
  @pg_query_params($vink, 'INSERT INTO vink_blips (owner, body) VALUES ($1, $2)',
                   array($vink_userid, $_POST['vink-message']));

  $blip_id_res
    = pg_query_params($vink, 'SELECT CURRVAL($1)', array('vink_blips_id_seq'));
  $blip_id_row = pg_fetch_row($blip_id_res);
  $blip_id = $blip_id_row[0];

  $participants = $_POST['vink-participants'];

  foreach($participants as $participant)
  {
    /* XXX: Verify that participant is in user's address list */

    pg_query_params($vink, 'INSERT INTO vink_participants (blip_id, contact) VALUES ($1, $2)',
                    array($blip_id, $participant));
  }

 /*
   "SELECT CURRVAL(
     pg_get_serial_sequence('my_tbl_name','id_col_name'));"
   */
  @pg_query($vink, 'COMMIT');
}

require_once('header.inc.php');

$contacts_res = @pg_query_params($vink, 'SELECT * FROM vink_contacts WHERE user_id = $1 ORDER BY name',
                                 array($vink_userid));
?>
<h1>Create new wave</h1>
<form class='new-wave' action='compose.php' method='post'>
  <div style='float:left'>
    <textarea name='vink-message' cols='80' rows='25'></textarea><br />
    <input type='submit' value='Save' />
  </div>
  <div style='float:left'>
    <h2>Participants</h2>
    <table class='participants'>
      <? while($contacts_row = @pg_fetch_array($contacts_res)) { ?>
        <tr>
          <td><input type='checkbox' name='vink-participants[]' value='<?=$contacts_row['id']?>' /></td>
          <td><span class='name'><?=$contacts_row['name']?></span><br /><span class='jid'><?=$contacts_row['jid']?></span></td>
        </tr>
      <? } ?>
    </table>
  </div>
</form>
<?
require_once('footer.inc.php');
?>
