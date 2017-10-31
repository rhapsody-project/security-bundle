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
namespace Rhapsody\SecurityBundle\Tests\Security\Http\RememberMe;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Http\RememberMe\ChainRememberMeServices;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;

/**
 *
 * @author sean.quinn
 */
class ChainRememberMeServicesTest extends TestCase
{

    private function generateRememberMeServices(array $map)
    {
        foreach ($map as $rememberMeServices) {
            yield $rememberMeServices;
        }
    }

    private function getRememberMeServicesMap($returnValues = [null, null, null])
    {
        $map = [];

        foreach ($returnValues as $value) {
            $map[] = $this->getRememberMeServicesMock($value);
        }

        return $map;
    }

    private function getRememberMeServicesMock($returnValue)
    {
        $rememberMeServices = $this->getMockBuilder(RememberMeServicesInterface::class)
        ->disableOriginalConstructor()
        ->getMock();

        if ($returnValue) {
            $rememberMeServices->expects($this->once())
                ->method('autoLogin')
                ->with($this->isInstanceOf(Request::class))
                ->willReturn($returnValue);
        }

        return $rememberMeServices;
    }

    public function testAddRememberMeServices()
    {
        $rememberMeServices = new ChainRememberMeServices($this->getRememberMeServicesMap());
        $custom = $this->getRememberMeServicesMock(null);
        $rememberMeServices->addRememberMeServices($custom);

        $map = [];
        foreach ($rememberMeServices as $child) {
            $map[] = $child;
        }

        $this->assertCount(4, $map);
        $this->assertContains($custom, $map);
    }

    public function testAutoLoginWhenChainedRememberMeServicesAllReturnNull()
    {
        $request = $this->createMock(Request::class);
        $map = $this->getRememberMeServicesMap();

        $chainRememberMeServices = new ChainRememberMeServices($map);
        $actual = $chainRememberMeServices->autoLogin($request);
        $this->assertNull($actual);
    }

    public function testAutoLoginWhenOneRememberMeServicesReturnsAToken()
    {
        $request = $this->createMock(Request::class);
        $token = $this->createMock(TokenInterface::class);
        $map = $this->getRememberMeServicesMap(array(null, $token, null));

        $chainRememberMeServices = new ChainRememberMeServices($map);
        $actual = $chainRememberMeServices->autoLogin($request);
        $this->assertNotNull($actual);
        $this->assertSame($token, $actual);
    }

    public function testClearMap()
    {
        $rememberMeServices = new ChainRememberMeServices($this->getRememberMeServicesMap());
        $rememberMeServices->clearMap();

        $this->assertFalse($rememberMeServices->getIterator()->valid());
    }

    public function testGetIterator()
    {
        $map = $this->getRememberMeServicesMap();

        $chainRememberMeServices = new ChainRememberMeServices($map);
        foreach ($chainRememberMeServices as $rememberMeServices) {
            $this->assertContains($rememberMeServices, $map);
        }
    }

    public function testRemoveRememberMeServices()
    {
        $rememberMeServices = new ChainRememberMeServices([]);
        $custom = $this->getRememberMeServicesMock(null);

        $rememberMeServices->addRememberMeServices($custom);
        $result = $rememberMeServices->removeRememberMeServices(function (RememberMeServicesInterface $rememberMeServices) use ($custom) {
            return $rememberMeServices instanceof \PHPUnit_Framework_MockObject_MockObject;
        });

        $this->assertTrue($result, 'removeExtractor returns true in case of success, false otherwise');
        $this->assertFalse($rememberMeServices->getIterator()
            ->valid(), 'The token extractor should have been removed so the map should be empty');
    }
}