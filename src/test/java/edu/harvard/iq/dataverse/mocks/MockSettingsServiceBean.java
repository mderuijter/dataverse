package edu.harvard.iq.dataverse.mocks;

import edu.harvard.iq.dataverse.settings.SettingsServiceBean;

public class MockSettingsServiceBean extends SettingsServiceBean {

	@Override
	public boolean isTrueForKey ( Key key, boolean defaultValue ) {
		return false;
	}
}
