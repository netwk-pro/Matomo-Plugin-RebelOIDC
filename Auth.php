<?php

/**
 * Matomo - free/libre analytics platform
 *
 * @link https://matomo.org
 * @license http://www.gnu.org/licenses/gpl-3.0.html GPL v3 or later
 *
 */

namespace Piwik\Plugins\RebelOIDC;

use Piwik\AuthResult;
use Piwik\Plugins\UsersManager\Model;

class Auth extends \Piwik\Plugins\Login\Auth
{
    /**
     * Forces a successful login after OIDC authentication.
     *
     * @var bool
     */
    protected $forceLogin = false;

    /**
     * @var Model
     */
    private $userModel;

    public function __construct()
    {
        parent::__construct();
        $this->userModel = new Model();
    }

    /**
     * @return AuthResult
     */
    public function authenticate()
    {
        if ($this->forceLogin) {
            if (empty($this->login)) {
                return new AuthResult(AuthResult::FAILURE, $this->login, null);
            }

            $user = $this->userModel->getUser($this->login);

            if (empty($user['login'])) {
                return new AuthResult(AuthResult::FAILURE, $this->login, null);
            }

            return $this->authenticationSuccess($user);
        }

        return parent::authenticate();
    }

    /**
     * @return AuthResult
     */
    private function authenticationSuccess(array $user)
    {
        $this->token_auth = $this->userModel->generateRandomTokenAuth();

        $isSuperUser = (int) $user['superuser_access'];
        $code = $isSuperUser
            ? AuthResult::SUCCESS_SUPERUSER_AUTH_CODE
            : AuthResult::SUCCESS;

        return new AuthResult(
            $code,
            $user['login'],
            $this->token_auth,
            ['token_access_level' => null]
        );
    }

    /**
     * @return bool
     */
    public function getForceLogin()
    {
        return $this->forceLogin;
    }

    public function setForceLogin(bool $forceLogin)
    {
        $this->forceLogin = $forceLogin;
    }
}
