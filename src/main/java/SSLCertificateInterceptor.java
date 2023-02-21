import com.appdynamics.agent.api.AppdynamicsAgent;
import com.appdynamics.agent.api.MetricPublisher;
import com.appdynamics.instrumentation.sdk.Rule;
import com.appdynamics.instrumentation.sdk.SDKClassMatchType;
import com.appdynamics.instrumentation.sdk.template.AGenericInterceptor;

import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SSLCertificateInterceptor extends AGenericInterceptor {

    @Override
    public List<Rule> initializeRules() {
        List<Rule> rules = new ArrayList<Rule>();
        rules.add(
                new Rule.Builder( "java.security.cert.X509Certificate").classMatchType(SDKClassMatchType.INHERITS_FROM_CLASS).methodMatchString("getInstance").build()
        );
        rules.add(
                new Rule.Builder( "java.security.cert.X509Certificate").classMatchType(SDKClassMatchType.MATCHES_CLASS).methodMatchString("getInstance").build()
        );
        rules.add(
                new Rule.Builder( "javax.security.cert.X509Certificate").classMatchType(SDKClassMatchType.IMPLEMENTS_INTERFACE).methodMatchString("getInstance").build()
        );
        return rules;
    }

    @Override
    public Object onMethodBegin(Object object, String className, String methodName, Object[] params) {
        return null;
    }

    @Override
    public void onMethodEnd(Object state, Object object, String className, String methodName, Object[] params, Throwable exception, Object returnVal) {
        getLogger().debug("SSLCertificateInterceptor intercepted call: java.security.cert.X509Certificate ==" + className +"."+ methodName +"()" );
        X509Certificate cert = (X509Certificate) returnVal;
        MetricPublisher metricPublisher = AppdynamicsAgent.getMetricPublisher();

        long daysToExpiration = ChronoUnit.DAYS.between(LocalDate.now(), new java.sql.Timestamp(cert.getNotAfter().getTime()).toLocalDateTime());
        String subject = cert.getSubjectX500Principal().getName();
        metricPublisher.reportObservedMetric("SSL Certificates|" + subject + "|Days To Expiration", daysToExpiration);
        getLogger().debug("SSLCertificateInterceptor published metric: Custom Metrics|SSL Certificates|" + subject + "|Days To Expiration = " + daysToExpiration);
        if (daysToExpiration <= 2) {
            AppdynamicsAgent.getTransaction().markAsError(
                    "This transaction may not fail due to this, but will in less than " + daysToExpiration + (daysToExpiration == 1 ? " day. " : " days. ") +
                            " Please contact the owner of certificate with subject: " + subject + "and inform them that updates are required ASAP!"
            );
            Map<String, String> eventInfoMap = new HashMap<>();
            eventInfoMap.put("SSL Certificate Subject",subject);
            eventInfoMap.put("Days To Expiration", String.valueOf(daysToExpiration));
            AppdynamicsAgent.getEventPublisher().publishEvent("SSL Certificate Expiration", "ERROR", "APPLICATION_ERROR", eventInfoMap);
        } else if (daysToExpiration <=14 ){
            Map<String, String> eventInfoMap = new HashMap<>();
            eventInfoMap.put("SSL Certificate Subject",subject);
            eventInfoMap.put("Days To Expiration", String.valueOf(daysToExpiration));
            AppdynamicsAgent.getEventPublisher().publishEvent("SSL Certificate Expiration", "WARN", "APPLICATION_ERROR", eventInfoMap);
        }
    }

}
