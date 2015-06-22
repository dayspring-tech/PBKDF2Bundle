<?php
namespace Dayspring\PBKDF2Bundle\Security\Core\User;

/**
 * TOTPUserInterface
 *
 * @author jeffreywong
 */
interface TOTPUserInterface extends PBKDF2UserInterface
{
	
	function getValidTOTPSecrets();
	
}
