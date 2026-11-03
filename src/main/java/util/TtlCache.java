package com.example.authserver.util;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

/** Tiny time-based cache. Values are reloaded after the TTL; concurrent loads of one key may run twice, which is harmless here. */
public final class TtlCache<K, V> {

    private record Entry<V>(V value, long loadedAtNanos) {
    }

    private final ConcurrentHashMap<K, Entry<V>> map = new ConcurrentHashMap<>();
    private final long ttlNanos;

    public TtlCache(Duration ttl) {
        this.ttlNanos = ttl.toNanos();
    }

    public V get(K key, Function<K, V> loader) {
        long now = System.nanoTime();
        Entry<V> entry = map.get(key);
        if (entry == null || now - entry.loadedAtNanos() > ttlNanos) {
            V value = loader.apply(key);
            map.put(key, new Entry<>(value, now));
            return value;
        }
        return entry.value();
    }
}
