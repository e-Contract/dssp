/*
 * Digital Signature Service Protocol Project.
 * Copyright (C) 2014-2020 e-Contract.be BV.
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

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.LogFactory;
import org.apache.felix.framework.Felix;
import org.apache.ws.security.conversation.ConversationException;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.exporter.ZipExporter;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.impl.base.exporter.zip.ZipExporterImpl;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.jboss.shrinkwrap.resolver.api.maven.MavenResolverSystem;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.e_contract.dssp.client.DigitalSignatureServiceClient;
import be.e_contract.dssp.ws.DigitalSignatureServiceFactory;
import be.e_contract.dssp.ws.jaxws.DigitalSignatureService;
import test.unit.be.e_contract.dssp.client.osgi.dependency.SomeClass;

public class OSGiTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(OSGiTest.class);

	private Felix felix;

	private File felixRootDir;

	@BeforeEach
	public void setUp() throws Exception {
		this.felixRootDir = File.createTempFile("felix-", "cache");
		this.felixRootDir.delete();
		this.felixRootDir.mkdir();
		Map<String, String> configuration = new HashMap<>();
		configuration.put("felix.cache.rootdir", this.felixRootDir.getAbsolutePath());
		configuration.put("org.osgi.framework.storage.clean", "onFirstInit");
		configuration.put("felix.log.level", "4");
		configuration.put("org.osgi.framework.bootdelegation", "com.sun.xml.internal.ws.api.message");
		this.felix = new Felix(configuration);
		this.felix.start();
	}

	@AfterEach
	public void tearDown() throws Exception {
		this.felix.stop();
		this.felix.waitForStop(1000);

		FileUtils.deleteDirectory(this.felixRootDir);
	}

	@Test
	public void testFelix() throws Exception {
		BundleContext bundleContext = this.felix.getBundleContext();
		Bundle[] bundles = bundleContext.getBundles();
		LOGGER.debug("number of bundles: {}", bundles.length);
		for (Bundle bundle : bundles) {
			LOGGER.debug("bundle symbolic name: {}", bundle.getSymbolicName());
		}

		File bundleFile = File.createTempFile("test-bundle", ".jar");
		bundleFile.deleteOnExit();
		JavaArchive bundleJar = ShrinkWrap.create(JavaArchive.class);
		bundleJar.addClass(MyBundleActivator.class);
		bundleJar.addAsManifestResource(new StringAsset(
				"Manifest-Version: 1.0" + '\n' + "Bundle-ManifestVersion: 2" + '\n' + "Bundle-Name: Hello World" + '\n'
						+ "Bundle-SymbolicName: helloworld" + '\n' + "Bundle-Activator: "
						+ MyBundleActivator.class.getName() + '\n' + "Import-Package: org.osgi.framework" + '\n'),
				"MANIFEST.MF");
		ZipExporter zipExporter = new ZipExporterImpl(bundleJar);
		zipExporter.exportTo(bundleFile, true);

		Bundle myBundle = bundleContext.installBundle(bundleFile.toURI().toURL().toString());
		LOGGER.debug("bundle state: {}", myBundle.getState());
		assertEquals(Bundle.INSTALLED, myBundle.getState());
		myBundle.start();
		LOGGER.debug("bundle state: {}", myBundle.getState());
		assertEquals(Bundle.ACTIVE, myBundle.getState());
		myBundle.stop();
		LOGGER.debug("bundle state: {}", myBundle.getState());
		assertEquals(Bundle.RESOLVED, myBundle.getState());

		bundles = bundleContext.getBundles();
		LOGGER.debug("number of bundles: {}", bundles.length);
		for (Bundle bundle : bundles) {
			LOGGER.debug("bundle symbolic name: {}", bundle.getSymbolicName());
		}
	}

	@Test
	public void testDependency() throws Exception {
		BundleContext bundleContext = this.felix.getBundleContext();
		Bundle[] bundles = bundleContext.getBundles();
		LOGGER.debug("number of bundles: {}", bundles.length);
		for (Bundle bundle : bundles) {
			LOGGER.debug("bundle symbolic name: {}", bundle.getSymbolicName());
		}

		File dependencyBundleFile = File.createTempFile("test-bundle", ".jar");
		dependencyBundleFile.deleteOnExit();
		JavaArchive dependencyBundleJar = ShrinkWrap.create(JavaArchive.class);
		dependencyBundleJar.addClass(SomeClass.class);
		dependencyBundleJar
				.addAsManifestResource(new StringAsset("Manifest-Version: 1.0" + '\n' + "Bundle-ManifestVersion: 2"
						+ '\n' + "Bundle-Name: A dependency" + '\n' + "Bundle-SymbolicName: org.dependency" + '\n'
						+ "Export-Package: " + SomeClass.class.getPackage().getName() + '\n'), "MANIFEST.MF");
		ZipExporter dependencyZipExporter = new ZipExporterImpl(dependencyBundleJar);
		dependencyZipExporter.exportTo(dependencyBundleFile, true);
		bundleContext.installBundle(dependencyBundleFile.toURI().toURL().toString());
		LOGGER.debug("exporting package: {}", SomeClass.class.getPackage().getName());

		LOGGER.debug("after installing dependency");
		bundles = bundleContext.getBundles();
		LOGGER.debug("number of bundles: {}", bundles.length);
		for (Bundle bundle : bundles) {
			LOGGER.debug("bundle symbolic name: {}", bundle.getSymbolicName());
		}

		File bundleFile = File.createTempFile("test-bundle", ".jar");
		bundleFile.deleteOnExit();
		JavaArchive bundleJar = ShrinkWrap.create(JavaArchive.class);
		bundleJar.addClass(DependentBundleActivator.class);
		bundleJar
				.addAsManifestResource(
						new StringAsset("Manifest-Version: 1.0" + '\n' + "Bundle-ManifestVersion: 2" + '\n'
								+ "Bundle-Name: Hello World" + '\n' + "Bundle-SymbolicName: helloworld" + '\n'
								+ "Import-Package: org.osgi.framework," + SomeClass.class.getPackage().getName() + '\n'
								+ "Bundle-Activator: " + DependentBundleActivator.class.getName() + '\n'),
						"MANIFEST.MF");
		ZipExporter zipExporter = new ZipExporterImpl(bundleJar);
		zipExporter.exportTo(bundleFile, true);

		Bundle myBundle = bundleContext.installBundle(bundleFile.toURI().toURL().toString());
		LOGGER.debug("bundle state: {}", myBundle.getState());
		assertEquals(Bundle.INSTALLED, myBundle.getState());
		myBundle.start();
		LOGGER.debug("bundle state: {}", myBundle.getState());
		assertEquals(Bundle.ACTIVE, myBundle.getState());
		myBundle.stop();
		LOGGER.debug("bundle state: {}", myBundle.getState());
		assertEquals(Bundle.RESOLVED, myBundle.getState());

		bundles = bundleContext.getBundles();
		LOGGER.debug("number of bundles: {}", bundles.length);
		for (Bundle bundle : bundles) {
			LOGGER.debug("bundle symbolic name: {}", bundle.getSymbolicName());
		}
	}

	// @Test
	public void testBundle() throws Exception {
		BundleContext bundleContext = this.felix.getBundleContext();
		Bundle[] bundles = bundleContext.getBundles();
		LOGGER.debug("number of bundles: {}", bundles.length);
		for (Bundle bundle : bundles) {
			LOGGER.debug("bundle symbolic name: {}", bundle.getSymbolicName());
		}

		MavenResolverSystem mavenResolverSystem = Maven.resolver();
		bundleContext.installBundle(mavenResolverSystem.resolve("org.apache.ws.security:wss4j:1.6.16")
				.withoutTransitivity().asSingleFile().toURI().toURL().toString());
		bundleContext.installBundle(mavenResolverSystem.resolve("org.apache.santuario:xmlsec:1.5.7")
				.withoutTransitivity().asSingleFile().toURI().toURL().toString());
		bundleContext.installBundle(mavenResolverSystem.resolve("commons-logging:commons-logging:1.2")
				.withoutTransitivity().asSingleFile().toURI().toURL().toString());

		File wsBundleFile = File.createTempFile("dssp-ws-", ".jar");
		wsBundleFile.deleteOnExit();
		JavaArchive wsBundleJar = ShrinkWrap.create(JavaArchive.class);
		wsBundleJar.addPackages(true, DigitalSignatureServiceFactory.class.getPackage());
		wsBundleJar.addAsManifestResource(new StringAsset(
				"Manifest-Version: 1.0" + '\n' + "Bundle-ManifestVersion: 2" + '\n' + "Bundle-Name: A dependency" + '\n'
						+ "Bundle-SymbolicName: " + DigitalSignatureServiceFactory.class.getPackage().getName() + '\n'
						+ "Import-Package: javax.xml.namespace, javax.xml.ws" + "\n" + "Export-Package: "
						+ DigitalSignatureServiceFactory.class.getPackage().getName() + ","
						+ DigitalSignatureService.class.getPackage().getName() + '\n'),
				"MANIFEST.MF");
		ZipExporter wsZipExporter = new ZipExporterImpl(wsBundleJar);
		wsZipExporter.exportTo(wsBundleFile, true);
		bundleContext.installBundle(wsBundleFile.toURI().toURL().toString());

		File clientBundleFile = File.createTempFile("dssp-client-", ".jar");
		clientBundleFile.deleteOnExit();
		JavaArchive dependencyBundleJar = ShrinkWrap.create(JavaArchive.class);
		dependencyBundleJar.addPackage(DigitalSignatureServiceClient.class.getPackage());
		dependencyBundleJar.addAsManifestResource(new StringAsset("Manifest-Version: 1.0" + '\n'
				+ "Bundle-ManifestVersion: 2" + '\n' + "Bundle-Name: A dependency" + '\n' + "Bundle-SymbolicName: "
				+ DigitalSignatureServiceClient.class.getPackage().getName() + '\n' + "Import-Package: "
				+ ConversationException.class.getPackage().getName() + "," + LogFactory.class.getPackage().getName()
				+ "," + DigitalSignatureServiceFactory.class.getPackage().getName() + ","
				+ DigitalSignatureService.class.getPackage().getName() + ","
				+ "javax.xml.ws, javax.xml.ws.handler, javax.activation, javax.xml.ws.handler.soap"
				+ ",org.w3c.dom,javax.xml.soap" + "\n" + "Export-Package: "
				+ DigitalSignatureServiceClient.class.getPackage().getName() + '\n'), "MANIFEST.MF");
		ZipExporter dependencyZipExporter = new ZipExporterImpl(dependencyBundleJar);
		dependencyZipExporter.exportTo(clientBundleFile, true);
		bundleContext.installBundle(clientBundleFile.toURI().toURL().toString());
		LOGGER.debug("exporting package: {}", DigitalSignatureServiceClient.class.getPackage().getName());

		LOGGER.debug("after installing dependency");
		bundles = bundleContext.getBundles();
		LOGGER.debug("number of bundles: {}", bundles.length);
		for (Bundle bundle : bundles) {
			LOGGER.debug("bundle symbolic name: {}", bundle.getSymbolicName());
		}

		File bundleFile = File.createTempFile("test-bundle", ".jar");
		bundleFile.deleteOnExit();
		JavaArchive bundleJar = ShrinkWrap.create(JavaArchive.class);
		bundleJar.addClass(DSSClientBundleActivator.class);
		bundleJar.addAsManifestResource(new StringAsset("Manifest-Version: 1.0" + '\n' + "Bundle-ManifestVersion: 2"
				+ '\n' + "Bundle-Name: Hello World" + '\n' + "Bundle-SymbolicName: helloworld" + '\n'
				+ "Import-Package: org.osgi.framework," + DigitalSignatureServiceClient.class.getPackage().getName()
				+ '\n' + "Bundle-Activator: " + DSSClientBundleActivator.class.getName() + '\n'), "MANIFEST.MF");
		ZipExporter zipExporter = new ZipExporterImpl(bundleJar);
		zipExporter.exportTo(bundleFile, true);

		Bundle myBundle = bundleContext.installBundle(bundleFile.toURI().toURL().toString());
		LOGGER.debug("bundle state: {}", myBundle.getState());
		assertEquals(Bundle.INSTALLED, myBundle.getState());
		myBundle.start();
		LOGGER.debug("bundle state: {}", myBundle.getState());
		assertEquals(Bundle.ACTIVE, myBundle.getState());
		myBundle.stop();
		LOGGER.debug("bundle state: {}", myBundle.getState());
		assertEquals(Bundle.RESOLVED, myBundle.getState());

		bundles = bundleContext.getBundles();
		LOGGER.debug("number of bundles: {}", bundles.length);
		for (Bundle bundle : bundles) {
			LOGGER.debug("bundle symbolic name: {}", bundle.getSymbolicName());
		}
	}
}
