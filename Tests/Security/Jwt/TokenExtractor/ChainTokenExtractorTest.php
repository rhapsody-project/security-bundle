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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\TokenExtractor;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\ChainTokenExtractor;
use Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\TokenExtractorInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 */
class ChainTokenExtractorTest extends TestCase
{

    public function testGetIterator()
    {
        $map = $this->getTokenExtractorMap();

        foreach ((new ChainTokenExtractor($map)) as $extractor) {
            $this->assertContains($extractor, $map);
        }
    }

    public function testAddExtractor()
    {
        $extractor = new ChainTokenExtractor($this->getTokenExtractorMap());
        $custom = $this->getTokenExtractorMock(null);
        $extractor->addExtractor($custom);

        $map = [];
        foreach ($extractor as $child) {
            $map[] = $child;
        }

        $this->assertCount(4, $map);
        $this->assertContains($custom, $map);
    }

    public function testRemoveExtractor()
    {
        $extractor = new ChainTokenExtractor([]);
        $custom = $this->getTokenExtractorMock(null);

        $extractor->addExtractor($custom);
        $result = $extractor->removeExtractor(function (TokenExtractorInterface $extractor) use ($custom) {
            return $extractor instanceof \PHPUnit_Framework_MockObject_MockObject;
        });

        $this->assertTrue($result, 'removeExtractor returns true in case of success, false otherwise');
        $this->assertFalse($extractor->getIterator()
            ->valid(), 'The token extractor should have been removed so the map should be empty');
    }

    public function testExtract()
    {
        $extractor = new ChainTokenExtractor($this->getTokenExtractorMap([false, false, 'dummy']));
        $this->assertEquals('dummy', $extractor->extract(new Request()));
    }

    public function testClearMap()
    {
        $extractor = new ChainTokenExtractor($this->getTokenExtractorMap());
        $extractor->clearMap();

        $this->assertFalse($extractor->getIterator()
            ->valid());
    }

    private function getTokenExtractorMock($returnValue)
    {
        $extractor = $this->getMockBuilder(TokenExtractorInterface::class)
            ->disableOriginalConstructor()
            ->getMock();

        if ($returnValue) {
            $extractor->expects($this->once())
                ->method('extract')
                ->with($this->isInstanceOf(Request::class))
                ->willReturn($returnValue);
        }

        return $extractor;
    }

    private function getTokenExtractorMap($returnValues = [null, null, null])
    {
        $map = [];

        foreach ($returnValues as $value) {
            $map[] = $this->getTokenExtractorMock($value);
        }

        return $map;
    }

    private function generateTokenExtractors(array $map)
    {
        foreach ($map as $extractor) {
            yield $extractor;
        }
    }
}
