<?
require_once('config.inc.php');

require_once('session.inc.php');
require_once('header.inc.php');
?>
  <div class='new-wave'><a href='compose.php'>Create new wave</a></div>
  <ul class='wave-list'>
    <li>
      <h2><a href='wave/1'>Det hadde kanskje vært fint med andre rutere ...</a></h2>
      <div class='participants'>
        <a class='person' href='person/1'>Bob Jensen</a>,
        <a class='person' href='person/2'>Knut Larsen</a>,
        <a class='person' href='person/3'>Aslak Hamp</a>
      </div>
    </li>
  </ul>
  <hr />
  <div class='blip'>
    <div class='participants'>
      <a class='person' href='person/1'>Bob Jensen</a> @ Tue Nov 10 01:51:05 CET 2009
    </div>
    <div class='content'>
      Det hadde kanskje vært fint med andre rutere, men vi må nok nøye
      oss med D-Link.
      <div class='actions'>[ <a href='reply'>Reply to this</a> &ndash; <a href='edit'>Edit</a> ]</div>
    </div>
    <div class='blip'>
      <div class='participants'>
        <a class='person' href='person/2'>Knut Larsen</a> @ Tue Nov 10 01:51:05 CET 2009 (2 edits)
      </div>
      <div class='content'>
        Det skjedde i de dager da keiser Augustus hadde lyst ut befaling
        om at hele befolkningen skulle innskrives i manntall.
        <div class='actions'>[ <a href='reply'>Reply to this</a> &ndash; <A href='edit'>Edit</a> ]</div>
      </div>
    </div>
  </div>
<?require_once('footer.inc.php');?>
