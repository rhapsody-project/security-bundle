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
namespace Rhapsody\SecurityBundle\Tests\Functional\Utils;

use Rhapsody\SecurityBundle\RhapsodySecurityEvents;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtAuthenticatedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtCreatedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtDecodedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtEncodedEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtExpiredEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtInvalidEvent;
use Rhapsody\SecurityBundle\Security\Jwt\Event\JwtNotFoundEvent;
use Symfony\Component\EventDispatcher\Event;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
 *
 * @author sean.quinn
 */
class CallableEventSubscriber implements EventSubscriberInterface
{
    private static $listeners     = [];
    private static $eventClassMap = [
        RhapsodySecurityEvents::JWT_CREATED       => JwtCreatedEvent::class,
        RhapsodySecurityEvents::JWT_DECODED       => JwtDecodedEvent::class,
        RhapsodySecurityEvents::JWT_INVALID       => JwtInvalidEvent::class,
        RhapsodySecurityEvents::JWT_NOT_FOUND     => JwtNotFoundEvent::class,
        RhapsodySecurityEvents::JWT_ENCODED       => JwtEncodedEvent::class,
        RhapsodySecurityEvents::JWT_AUTHENTICATED => JwtAuthenticatedEvent::class,
        RhapsodySecurityEvents::JWT_EXPIRED       => JwtExpiredEvent::class,
    ];

    /**
     */
    public static function clear()
    {
        foreach (self::$listeners as $eventName => $listener) {
            self::unsetListener($eventName);
        }
    }

    public static function getSubscribedEvents()
    {
        $subscriberMap = [];

        foreach (self::$eventClassMap as $name => $className) {
            if (self::hasListener($name)) {
                $subscriberMap[$name] = 'handleEvent';
            }
        }

        return $subscriberMap;
    }

    /**
     * Executes the good listener depending on the passed event.
     *
     * @param Event $event An instance of one of the events
     *                     defined in {@link self::$eventClassMap}
     */
    public function handleEvent(Event $event)
    {
        $eventName = array_search(get_class($event), self::$eventClassMap);

        if (!$eventName) {
            return;
        }

        $listener = self::getListener($eventName);

        if ($listener instanceof \Closure) {
            return $listener($event);
        }

        call_user_func($listener, $event);
    }

    /**
     * Checks whether a listener is registered for this event.
     *
     * @param string $eventName
     *
     * @return bool
     */
    public static function hasListener($eventName)
    {
        return isset(self::$listeners[$eventName]);
    }

    /**
     * Gets the listener for this event.
     *
     * @param string $eventName The event for which to retrieve the listener
     *
     * @return callable
     */
    public static function getListener($eventName)
    {
        if (!self::hasListener($eventName)) {
            return;
        }

        return self::$listeners[$eventName];
    }

    /**
     * Set the listener to use for a given event.
     *
     * @param string   $eventName The event to listen on
     * @param callable $listener  The callback to be executed for this event
     */
    public static function setListener($eventName, callable $listener)
    {
        self::$listeners[$eventName] = $listener;
    }

    /**
     * Unset the listener for a given event.
     *
     * @param string $eventName The event for which to unset the listener
     */
    public static function unsetListener($eventName)
    {
        if (!self::hasListener($eventName)) {
            return;
        }

        unset(self::$listeners[$eventName]);
    }
}
