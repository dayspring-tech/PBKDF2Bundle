<?php
namespace Dayspring\PBKDF2Bundle\Security\Core\Authentication\Token;


/**
 * TOTPUsernamePasswordToken
 *
 * @author jeffreywong
 */
class TOTPUsernamePasswordToken extends \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken
{
	protected $token;

	/**
     * Constructor.
     *
     * @param string|object            $user        The username (like a nickname, email address, etc.), or a UserInterface instance or an object implementing a __toString method.
     * @param string                   $credentials This usually is the password of the user
     * @param string                   $token		This usually is the one time token
     * @param string                   $providerKey The provider key
     * @param RoleInterface[]|string[] $roles       An array of roles
     *
     * @throws \InvalidArgumentException
     */
    public function __construct($user, $credentials, $token, $providerKey, array $roles = array())
    {
        parent::__construct($user, $credentials, $providerKey, $roles);

		$this->token = $token;
    }
	
	public function getToken()
	{
		return $this->token;
	}
	
	/**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize(array($this->token, parent::serialize()));
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        list($this->token, $parentStr) = unserialize($serialized);
        parent::unserialize($parentStr);
    }	
}
