package com.quantumvpn.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;

public final class RevokingTestVpnService extends VpnService {
    public static final String ACTION_STOP = "com.quantumvpn.test.STOP_REVOKER";
    private static final String CHANNEL_ID = "gate-revoke-vpn";
    private static final int NOTIFICATION_ID = 9001;
    private ParcelFileDescriptor descriptor;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            closeDescriptor();
            stopForeground(STOP_FOREGROUND_REMOVE);
            stopSelf();
            return START_NOT_STICKY;
        }
        showForeground();
        if (prepare(this) != null) {
            stopSelf();
            return START_NOT_STICKY;
        }
        descriptor = new Builder()
                .setSession("Gate revoke VPN")
                .addAddress("10.111.0.1", 30)
                .addRoute("0.0.0.0", 0)
                .establish();
        if (descriptor == null) stopSelf();
        return START_NOT_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return super.onBind(intent);
    }

    @Override
    public void onDestroy() {
        closeDescriptor();
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }

    private void closeDescriptor() {
        if (descriptor != null) {
            try {
                descriptor.close();
            } catch (Exception ignored) {
                // Test cleanup remains idempotent.
            }
            descriptor = null;
        }
    }

    private void showForeground() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(
                new NotificationChannel(CHANNEL_ID, "Gate VPN", NotificationManager.IMPORTANCE_MIN));
        Notification notification = new Notification.Builder(this, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle("Gate revoke VPN")
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        } else {
            startForeground(NOTIFICATION_ID, notification);
        }
    }
}
