<?php
/* Copyright (c) Rhapsody Project
 *
 * Licensed under the MIT License (http://opensource.org/licenses/MIT)
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
 * OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
namespace Rhapsody\SecurityBundle\Tests\Functional;

use Rhapsody\SecurityBundle\Tests\Functional\Utils\CallableEventSubscriber;
use Symfony\Component\BrowserKit\Cookie;
use Symfony\Component\HttpKernel\Client;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 *
 * @author sean.quinn
 *
 */
abstract class AbstractLoginTest extends WebTestCase
{

    private $authenticationException;

    /**
     * The test case to select from, e.g. <code>jwt/FormLogin</code>,
     * <code>jwt/JsonLogin</code>, etc.
     * @var string
     */
    protected static $testCase;

    protected static function addTokenToClient(Client &$client, $tokenStorage, $token)
    {
        if ('cookie' === strtolower($tokenStorage)) {
            $client->getCookieJar()->set(new Cookie('BEARER', $token));
        }
        else {
            $client->setServerParameter('HTTP_AUTHORIZATION', sprintf('Bearer %s', $token));
        }
    }

    /**
     * Creates an authenticated client.
     *
     * @param array $options The array of options to pass into the client
     *     factory.
     * @param array $server The array of server parameters to initialize a
     *     client with.
     * @param string $username The username to authenticate with.
     *     (Default: 'jameskirk')
     * @param string $password The password to authenticate a user with.
     *     (Default: 'enterprise')
     * @return \Symfony\Component\HttpKernel\Client The authenticated client.
     */
    abstract protected static function createAuthenticatedClient(array $options = array(), array $server = array(), $username = 'jameskirk', $password = 'enterprise');

    /**
     * Creates a Client.
     *
     * @param array $options An array of options to pass to the createKernel class
     * @param array $server  An array of server parameters
     *
     * @return Client A Client instance
     */
    protected static function createClient(array $options = array(), array $server = array())
    {
        if (!array_key_exists('test_case', $options)) {
            $options['test_case'] = static::$testCase;
        }

        static::bootKernel($options);
        $client = static::$kernel->getContainer()->get('test.client');
        $client->setServerParameters($server);
        return $client;
    }

    /**
     * Convenience method for extracting the raw JSON Web Token used for
     * authorization from the client.
     *
     * @param Client $client the client.
     * @return string|null the raw authorization token or <code>null</code> if
     *     it is not set.
     */
    protected static function extractRawToken(Client $client, $location = 'header')
    {
        if ('cookie' === strtolower($location)) {
            $cookie = $client->getCookieJar()->get('BEARER');
            return $cookie->getValue();
        }
        elseif ('header' === strtolower($location)) {
            $header = $client->getServerParameter('HTTP_AUTHORIZATION', null);
            return substr($header, 7);
        }
        throw new \RuntimeException(sprintf('The location: "%s" is unknown. Unable to extract raw token.', $location));
    }

    protected function setUp()
    {
        // TODO: Figure out how to listen in to an authentication failure, so that we can report on it at the end of a test run...
        // CallableEventSubscriber::setListener(AuthenticationRhapsodySecurityEvents::AUTHENTICATION_FAILURE, function (AuthenticationFailureEvent $e) {
        //     $this->authenticationException = $e->getAuthenticationException();
        // });
        parent::setUp();
    }

    public static function setUpBeforeClass()
    {
        parent::deleteTmpDir(static::$testCase);
        parent::setUpBeforeClass();
    }

    protected function tearDown()
    {
        CallableEventSubscriber::clear();
        $this->authenticationException = null;
        parent::tearDown();
    }

    public static function tearDownAfterClass()
    {
        parent::deleteTmpDir(static::$testCase);
        parent::tearDownAfterClass();
    }

    /**
     * Return the configuration files to use for testing.
     */
    abstract function getConfigs();

    /**
     * @dataProvider getConfigs
     */
    public function testRequestSecuredRouteWithAuthorizationHeader($config)
    {
        $client = static::createAuthenticatedClient(array('root_config' => $config, 'debug' => true));
        $client->request('GET', '/profile');

        $response = $client->getResponse();
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals(200, $response->getStatusCode());

        $content = $response->getContent();
        $this->assertEquals('Profile', $content);
    }

    /**
     * @dataProvider getConfigs
     */
    public function testRequestSecuredRouteWithCookie($config)
    {
        $client = static::createAuthenticatedClient(array('root_config' => $config, 'debug' => true, 'store_token_in' => 'cookie'));
        $client->request('GET', '/profile');

        $response = $client->getResponse();
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals(200, $response->getStatusCode());

        $content = $response->getContent();
        $this->assertEquals('Profile', $content);
    }

    /**
     * @dataProvider getConfigs
     */
    public function testRefresh($config)
    {
        $client = static::createAuthenticatedClient(array('root_config' => $config, 'debug' => true));

        /** @var $decoder \Rhapsody\SecurityBundle\Security\Jwt\Encoder\JwtEncoderInterface */
        $decoder = static::$kernel->getContainer()->get('rhapsody_security.jwt_encoder');

        // ** Original [raw] token and payload
        $originalRawToken = static::extractRawToken($client);
        $originalTokenPayload = $decoder->decode($originalRawToken);

        // **
        // We wait for one (1) second before we attempt to refresh the token.
        // By waiting at least one second, we ensure different values for the
        // issued at and expiration claims. [SWQ]
        sleep(1);
        $client->request('POST', '/auth/refresh');

        // ** 1. Assert the request was successful, and we have content.
        $response = $client->getResponse();
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertNotEmpty($response->getContent());

        // ** 2. Assert the response contains the [refreshed] token.
        $actual = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('token', $actual, 'The response should have a "token" key containing a JWT token.');
        $this->assertNotEmpty($actual['token']);
        $this->assertNotSame($originalRawToken, $actual['token']);

        // ** 3. Assert the refreshed token against the original (the only
        //       differences here should be time stamps).
        $actual = $decoder->decode($actual['token']);
        $this->assertArraySubset(array(
            'username' => 'jameskirk',
            'roles' => array('ROLE_USER')
        ), $actual);
        $this->assertThat($actual['iat'], $this->greaterThan($originalTokenPayload['iat']));
        $this->assertThat($actual['exp'], $this->greaterThan($originalTokenPayload['exp']));
    }

    /**
     * @dataProvider getConfigs
     */
    public function testRefreshWithCookie($config)
    {
        $client = static::createAuthenticatedClient(array('root_config' => $config, 'debug' => true, 'store_token_in' => 'cookie'));

        /** @var $decoder \Rhapsody\SecurityBundle\Security\Jwt\Encoder\JwtEncoderInterface */
        $decoder = static::$kernel->getContainer()->get('rhapsody_security.jwt_encoder');

        // ** Original [raw] token and payload
        $originalRawToken = static::extractRawToken($client, 'cookie');
        $originalTokenPayload = $decoder->decode($originalRawToken);

        // **
        // We wait for one (1) second before we attempt to refresh the token.
        // By waiting at least one second, we ensure different values for the
        // issued at and expiration claims. [SWQ]
        sleep(1);
        $client->request('POST', '/auth/refresh');

        // ** 1. Assert the request was successful, and we have content.
        $response = $client->getResponse();
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertNotEmpty($response->getContent());

        // ** 2. Assert the response contains the [refreshed] token.
        $actual = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('token', $actual, 'The response should have a "token" key containing a JWT token.');
        $this->assertNotEmpty($actual['token']);
        $this->assertNotSame($originalRawToken, $actual['token']);

        // ** 3. Assert the refreshed token against the original (the only
        //       differences here should be time stamps).
        $actual = $decoder->decode($actual['token']);
        $this->assertArraySubset(array(
            'username' => 'jameskirk',
            'roles' => array('ROLE_USER')
        ), $actual);
        $this->assertThat($actual['iat'], $this->greaterThan($originalTokenPayload['iat']));
        $this->assertThat($actual['exp'], $this->greaterThan($originalTokenPayload['exp']));
    }

    /**
     * @dataProvider getConfigs
     */
    public function testRefreshWithJsonBody($config)
    {
        $client = static::createAuthenticatedClient(array('root_config' => $config, 'debug' => true));

        /** @var $decoder \Rhapsody\SecurityBundle\Security\Jwt\Encoder\JwtEncoderInterface */
        $decoder = static::$kernel->getContainer()->get('rhapsody_security.jwt_encoder');

        // ** Original [raw] token and payload
        $originalRawToken = static::extractRawToken($client);
        $originalTokenPayload = $decoder->decode($originalRawToken);

        // **
        // We wait for one (1) second before we attempt to refresh the token.
        // By waiting at least one second, we ensure different values for the
        // issued at and expiration claims. [SWQ]
        sleep(1);
        $jsonBody = json_encode(array('token' => $originalRawToken));
        $client->request('POST', '/auth/refresh', array(), array(), array(
            'HTTP_AUTHORIZATION' => null
        ), $jsonBody);

        // ** 1. Assert the request was successful, and we have content.
        $response = $client->getResponse();
        $this->assertTrue($response->isSuccessful());
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertNotEmpty($response->getContent());

        // ** 2. Assert the response contains the [refreshed] token.
        $actual = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('token', $actual, 'The response should have a "token" key containing a JWT token.');
        $this->assertNotEmpty($actual['token']);
        $this->assertNotSame($originalRawToken, $actual['token']);

        // ** 3. Assert the refreshed token against the original (the only
        //       differences here should be time stamps).
        $actual = $decoder->decode($actual['token']);
        $this->assertArraySubset(array(
            'username' => 'jameskirk',
            'roles' => array('ROLE_USER')
        ), $actual);
        $this->assertThat($actual['iat'], $this->greaterThan($originalTokenPayload['iat']));
        $this->assertThat($actual['exp'], $this->greaterThan($originalTokenPayload['exp']));
    }
}