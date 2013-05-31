<?php
namespace Dayspring\PBKDF2Bundle\Security\Core\User;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * Extend UserInterface to include iterations for PBKDF2.
 *
 * @author jwong
 */
interface PBKDF2UserInterface extends UserInterface {
    
    
    
    function getIterations();
	
	function setLastLogin($date);
}

?>
