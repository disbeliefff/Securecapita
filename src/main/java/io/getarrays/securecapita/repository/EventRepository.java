package io.getarrays.securecapita.repository;

import io.getarrays.securecapita.domain.UserEvent;
import io.getarrays.securecapita.enumeration.EventType;

import java.util.Collection;

public interface EventRepository {
    Collection<UserEvent> getEventByUserId (Long userId);
    void addUserEvent (String email, EventType eventType, String device, String ipAddress);
    void addUserEvent (Long userId, EventType eventType, String device, String ipAddress);
}
