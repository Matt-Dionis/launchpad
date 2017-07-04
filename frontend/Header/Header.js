/* @flow */

import React, { Component } from 'react';
import type { Pad, User } from '../types';
import HeaderLogo from './HeaderLogo';
import UserBar from './UserBar';
import HeaderButton from './HeaderButton';
import TitleEditor from './TitleEditor';
import './Header.less';

export default class Header extends Component {
  props: {|
    pad: Pad,
    user: ?User,
    isDeploying: boolean,
    onDeploy: () => any,
    onReset: () => any,
    onFork: () => any,
    onDownload: () => any,
    onLogin: () => any,
    onLogout: () => any,
    onSetTitle: (title: string) => any,
    onSetDescription: (description: string) => any,
  |};

  renderDeployButton() {
    let disabled;
    let tooltip;
    let onClick;
    if (!this.props.user) {
      disabled = true;
      tooltip = 'You need to login to save';
    } else if (
      this.props.pad.user &&
      this.props.user &&
      this.props.user.id !== this.props.pad.user.id
    ) {
      tooltip = "You can't save pads you don't own";
    } else if (this.props.pad.isDraft) {
      disabled = false;
      onClick = this.props.onDeploy;
    } else if (this.props.isDeploying) {
      disabled = true;
    } else {
      disabled = true;
      tooltip = 'Already up to date';
    }
    return (
      <HeaderButton tooltip={tooltip} disabled={disabled} onClick={onClick}>
        Save
      </HeaderButton>
    );
  }

  renderForkButton() {
    let disabled;
    let tooltip;
    let onClick;
    if (!this.props.user) {
      disabled = true;
      tooltip = 'You need to login to fork';
    } else if (!this.props.pad.isDeployed) {
      disabled = true;
      tooltip = 'This pad is not saved yet';
    } else if (this.props.isDeploying) {
      disabled = true;
    } else {
      disabled = false;
      onClick = this.props.onFork;
    }
    return (
      <HeaderButton tooltip={tooltip} disabled={disabled} onClick={onClick}>
        Fork
      </HeaderButton>
    );
  }

  renderDownloadButton() {
    let disabled;
    let tooltip;
    let onClick;
    if (!this.props.pad.isDeployed) {
      disabled = true;
      tooltip = 'Save this pad to download it';
    } else if (this.props.isDeploying) {
      disabled = true;
    } else if (this.props.pad.isDraft) {
      disabled = true;
      onClick = this.props.onDeploy;
      tooltip = 'Save this pad to download it';
    } else {
      disabled = false;
      onClick = this.props.onDownload;
    }
    return (
      <HeaderButton tooltip={tooltip} disabled={disabled} onClick={onClick}>
        Download
      </HeaderButton>
    );
  }

  render() {
    return (
      <div className="Header">
        <div className="Header-Left">
          <HeaderLogo />

          <div className="Management-Buttons">
            <HeaderButton onClick={() => (document.location.href = `/new`)}>
              New
            </HeaderButton>
            {this.renderDeployButton()}
            {this.renderDownloadButton()}
            {this.renderForkButton()}
          </div>

          <TitleEditor
            onSetTitle={this.props.onSetTitle}
            title={this.props.pad.title}
            githubUsername={
              this.props.pad.user && this.props.pad.user.githubUsername
            }
            canEdit={Boolean(
              !this.props.pad.user ||
                (this.props.user &&
                  this.props.pad.user.id === this.props.user.id),
            )}
          />
        </div>
        <div className="Header-Gap" />
        <div className="Header-Right">
          <UserBar
            user={this.props.user}
            onLogin={this.props.onLogin}
            onLogout={this.props.onLogout}
          />
        </div>
      </div>
    );
  }
}
