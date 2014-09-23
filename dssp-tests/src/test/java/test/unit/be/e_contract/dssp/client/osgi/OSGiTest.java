/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2014 e-Contract.be BVBA.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.unit.be.e_contract.dssp.client.osgi;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.felix.framework.Felix;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.impl.base.exporter.zip.ZipExporterImpl;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.jboss.shrinkwrap.resolver.api.maven.MavenResolverSystem;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;

import be.e_contract.dssp.client.DigitalSignatureServiceClient;

public class OSGiTest {

	private static final Log LOG = LogFactory.getLog(OSGiTest.class);

	private Felix felix;

	private File felixRootDir;

	@Before
	public void setUp() throws Exception {
		this.felixRootDir = File.createTempFile("felix-", "cache");
		this.felixRootDir.delete();
		this.felixRootDir.mkdir();
		Map<String, String> configuration = new HashMap<String, String>();
		configuration.put("felix.cache.rootdir",
				this.felixRootDir.getAbsolutePath());
		configuration.put("org.osgi.framework.storage.clean", "onFirstInit");
		configuration.put("felix.log.level", "4");
		configuration.put("org.osgi.framework.bootdelegation",
				"com.sun.xml.internal.ws.api.message");
		this.felix = new Felix(configuration);
		this.felix.start();
	}

	@After
	public void tearDown() throws Exception {
		this.felix.stop();
		this.felix.waitForStop(1000);

		FileUtils.deleteDirectory(this.felixRootDir);
	}

	@Test
	public void testMavenBundle() throws Exception {
		BundleContext bundleContext = this.felix.getBundleContext();
		Bundle[] bundles = bundleContext.getBundles();
		LOG.debug("number of bundles: " + bundles.length);
		for (Bundle bundle : bundles) {
			LOG.debug("bundle symbolic name: " + bundle.getSymbolicName());
		}

		MavenResolverSystem mavenResolverSystem = Maven.resolver();
		bundleContext.installBundle(mavenResolverSystem
				.resolve("org.apache.ws.security:wss4j:1.6.16")
				.withoutTransitivity().asSingleFile().toURI().toURL()
				.toString());
		bundleContext.installBundle(mavenResolverSystem
				.resolve("org.apache.santuario:xmlsec:1.5.7")
				.withoutTransitivity().asSingleFile().toURI().toURL()
				.toString());
		bundleContext.installBundle(mavenResolverSystem
				.resolve("commons-logging:commons-logging:1.2")
				.withoutTransitivity().asSingleFile().toURI().toURL()
				.toString());
		bundleContext.installBundle(mavenResolverSystem
				.resolve("javax.mail:mail:1.4.5").withoutTransitivity()
				.asSingleFile().toURI().toURL().toString());
		bundleContext.installBundle(mavenResolverSystem
				.resolve("commons-io:commons-io:2.4").withoutTransitivity()
				.asSingleFile().toURI().toURL().toString());
		bundleContext.installBundle(mavenResolverSystem
				.resolve("joda-time:joda-time:1.6.2").withoutTransitivity()
				.asSingleFile().toURI().toURL().toString());

		bundleContext.installBundle(Maven.resolver().loadPomFromFile("pom.xml")
				.resolve("be.e_contract.dssp:dssp-ws").withoutTransitivity()
				.asSingleFile().toURI().toURL().toString());
		mavenResolverSystem.loadPomFromFile("pom.xml");
		bundleContext.installBundle(Maven.resolver().loadPomFromFile("pom.xml")
				.resolve("be.e_contract.dssp:dssp-client")
				.withoutTransitivity().asSingleFile().toURI().toURL()
				.toString());

		LOG.debug("after installing dependency");
		bundles = bundleContext.getBundles();
		LOG.debug("number of bundles: " + bundles.length);
		for (Bundle bundle : bundles) {
			LOG.debug("bundle symbolic name: " + bundle.getSymbolicName());
		}

		File bundleFile = File.createTempFile("test-bundle", ".jar");
		bundleFile.deleteOnExit();
		JavaArchive bundleJar = ShrinkWrap.create(JavaArchive.class);
		bundleJar.addClass(DSSClientBundleActivator.class);
		bundleJar.addAsManifestResource(
				new StringAsset("Manifest-Version: 1.0"
						+ '\n'
						+ "Bundle-ManifestVersion: 2"
						+ '\n'
						+ "Bundle-Name: Hello World"
						+ '\n'
						+ "Bundle-SymbolicName: helloworld"
						+ '\n'
						+ "Import-Package: org.osgi.framework,"
						+ DigitalSignatureServiceClient.class.getPackage()
								.getName() + '\n' + "Bundle-Activator: "
						+ DSSClientBundleActivator.class.getName() + '\n'),
				"MANIFEST.MF");
		ZipExporter zipExporter = new ZipExporterImpl(bundleJar);
		zipExporter.exportTo(bundleFile, true);

		Bundle myBundle = bundleContext.installBundle(bundleFile.toURI()
				.toURL().toString());
		LOG.debug("bundle state: " + myBundle.getState());
		assertEquals(Bundle.INSTALLED, myBundle.getState());
		myBundle.start();
		LOG.debug("bundle state: " + myBundle.getState());
		assertEquals(Bundle.ACTIVE, myBundle.getState());
		myBundle.stop();
		LOG.debug("bundle state: " + myBundle.getState());
		assertEquals(Bundle.RESOLVED, myBundle.getState());

		bundles = bundleContext.getBundles();
		LOG.debug("number of bundles: " + bundles.length);
		for (Bundle bundle : bundles) {
			LOG.debug("bundle symbolic name: " + bundle.getSymbolicName());
		}
	}
}
