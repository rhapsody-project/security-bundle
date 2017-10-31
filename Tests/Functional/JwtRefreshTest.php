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

use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtCreatedEvent;

/**
 *
 * @author sean.quinn
 *
 */
final class JwtRefreshTest extends AbstractLoginTest
{

    public static function setUpBeforeClass()
    {
        static::$testCase = 'jwt/JwtRefresh';
        parent::setUpBeforeClass();
    }

    /**
     * {@inheritDoc}
     * @see \Rhapsody\SecurityBundle\Tests\Functional\AbstractLoginTest::createAuthenticatedClient()
     */
    protected static function createAuthenticatedClient(array $options = array(), array $server = array(), $username = 'jameskirk', $password = 'enterprise')
    {
        $client = self::createClient($options, $server);
        $credentials = array('_username' => $username, '_password' => $password);
        $client->request('POST', '/auth/login_check', array(), array(), array(
            'HTTP_CONTENT_TYPE' => 'application/json'
        ), json_encode($credentials));

        $response = $client->getResponse();
        $content = $response->getContent();
        $data = json_decode($content, true);
        $token = $data['token'];

        $tokenStorage = isset($options['store_token_in']) ? $options['store_token_in'] : 'header';
        static::addTokenToClient($client, $tokenStorage, $token);
        return $client;
    }

    public function getConfigs()
    {
        return array(
            array('config_default.yml'),
            array('config_lcobucci.yml'),
        );
    }

    /**
     * @dataProvider getConfigs
     */
    public function testLogin($config)
    {
        $client = self::createClient(array('root_config' => $config, 'debug' => true));
        $credentials = array('_username' => 'jameskirk', '_password' => 'enterprise');
        $client->request('POST', '/auth/login_check', array(), array(), array(
                'HTTP_CONTENT_TYPE' => 'application/json'
        ), json_encode($credentials));

        $response = $client->getResponse();
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertNotEmpty($response->getContent());

        $actual = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('token', $actual, 'The response should have a "token" key containing a JWT token.');
        $this->assertNotEmpty($actual['token']);
    }

    /**
     * @dataProvider getConfigs
     */
    public function testLoginWithCustomClaim($config)
    {
        $client = self::createClient(array('root_config' => $config, 'debug' => true));

        // ** Add custom data to the JWT token, in response to the JWT_CREATED event.
        $subscriber = static::$kernel->getContainer()->get('rhapsody_security.test.jwt_event_subscriber');
        $subscriber->setListener(RhapsodySecurityEvents::JWT_CREATED, function (JwtCreatedEvent $e) {
            $e->setData($e->getData() + ['custom' => 'dummy']);
        });

        // ** Make the request for the login page.
        $credentials = array('_username' => 'jameskirk', '_password' => 'enterprise');
        $client->request('POST', '/auth/login_check', array(), array(), array(
                'HTTP_CONTENT_TYPE' => 'application/json'
        ), json_encode($credentials));

        $response = $client->getResponse();
        $this->assertEquals(200, $response->getStatusCode());
        $this->assertNotEmpty($response->getContent());

        $body = json_decode($response->getContent(), true);
        $decoder = static::$kernel->getContainer()->get('rhapsody_security.jwt_encoder');
        $payload = $decoder->decode($body['token']);
        $this->assertArrayHasKey('custom', $payload, 'The payload should contains a "custom" claim.');
        $this->assertSame('dummy', $payload['custom'], 'The "custom" claim should be equal to "dummy".');
    }

    /**
     * @dataProvider getConfigs
     */
    public function testLoginWithInvalidCredentials($config)
    {
        $client = self::createClient(array('root_config' => $config, 'debug' => true));
        $credentials = array('_username' => 'spock', '_password' => 'livelongandprosper');
        $client->request('POST', '/auth/login_check', array(), array(), array(
                'HTTP_CONTENT_TYPE' => 'application/json'
        ), json_encode($credentials));

        $response = $client->getResponse();
        $this->assertFalse($response->isSuccessful());
        $this->assertSame(401, $response->getStatusCode());
        $this->assertNotEmpty($response->getContent());

        $body = json_decode($response->getContent(), true);
        $this->assertArrayHasKey('message', $body, 'The response should have a "message" key containing the failure reason.');
        $this->assertArrayHasKey('code', $body, 'The response should have a "code" key containing the response status code.');
        $this->assertSame('Bad credentials', $body['message']);
        $this->assertSame(401, $body['code']);
    }

}