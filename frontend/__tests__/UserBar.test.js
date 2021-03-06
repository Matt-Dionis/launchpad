/* @flow */

import React from 'react';
import UserBar from '../Header/UserBar';
import { mount } from 'enzyme';
import serializer from 'enzyme-to-json/serializer';

expect.addSnapshotSerializer(serializer);

test('renders normal', () => {
  const component = mount(
    <UserBar
      user={{
        id: 'test-id',
        githubUsername: 'example',
        pads: [],
      }}
      onLogin={() => {}}
      onLogout={() => {}}
    />,
  );
  expect(component).toMatchSnapshot();

  component.find('HeaderButton').simulate('click');
  expect(component).toMatchSnapshot();

  component.find('HeaderButton').simulate('click');
  expect(component).toMatchSnapshot();
});
