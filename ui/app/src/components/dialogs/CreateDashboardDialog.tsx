// Copyright 2023 The Perses Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { Dispatch, DispatchWithoutAction, useState } from 'react';
import { Button, FormControlLabel, MenuItem, Stack, Switch, TextField } from '@mui/material';
import { Dialog } from '@perses-dev/components';
import { Controller, FormProvider, SubmitHandler, useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { DashboardSelector, EphemeralDashboardInfo } from '@perses-dev/core';
import {
  CreateDashboardValidationType,
  CreateEphemeralDashboardValidationType,
  useDashboardValidationSchema,
  useEphemeralDashboardValidationSchema,
} from '../../validation';

interface CreateDashboardProps {
  open: boolean;
  projectOptions: string[];
  hideProjectSelect?: boolean;
  mode?: 'create' | 'duplicate';
  name?: string;
  onClose: DispatchWithoutAction;
  onSuccess?: Dispatch<DashboardSelector | EphemeralDashboardInfo>;
}

/**
 * Dialog used to create a dashboard.
 * @param props.open Define if the dialog should be opened or not.
 * @param props.projectOptions The project where the dashboard will be created.
 * If it contains only one element, it will be used as project value and will hide the project selection.
 * @param props.onClose Provides the function to close itself.
 * @param props.onSuccess Action to perform when user confirmed.
 */
export const CreateDashboardDialog = (props: CreateDashboardProps) => {
  const { open, projectOptions, hideProjectSelect, mode, name, onClose, onSuccess } = props;

  const [isTempCopyChecked, setTempCopyChecked] = useState<boolean>(false);
  const action = mode == 'duplicate' ? 'Duplicate' : 'Create';

  // Dashboard-related consts

  const dashboardSchemaValidation = useDashboardValidationSchema();

  const dashboardForm = useForm<CreateDashboardValidationType>({
    resolver: zodResolver(dashboardSchemaValidation),
    mode: 'onBlur',
    defaultValues: { dashboardName: '', projectName: projectOptions[0] },
  });

  const processDashboardForm: SubmitHandler<CreateDashboardValidationType> = (data) => {
    onClose();
    if (onSuccess) {
      onSuccess({ project: data.projectName, dashboard: data.dashboardName } as DashboardSelector);
    }
  };

  // Ephemeral Dashboard-related consts

  const ephemeralDashboardSchemaValidation = useEphemeralDashboardValidationSchema();

  const ephemeralDashboardForm = useForm<CreateEphemeralDashboardValidationType>({
    resolver: zodResolver(ephemeralDashboardSchemaValidation),
    mode: 'onBlur',
    defaultValues: { dashboardName: '', projectName: projectOptions[0], ttl: '' },
  });

  const processEphemeralDashboardForm: SubmitHandler<CreateEphemeralDashboardValidationType> = (data) => {
    onClose();
    if (onSuccess) {
      onSuccess({
        project: data.projectName,
        dashboard: data.dashboardName,
        ttl: data.ttl,
      } as EphemeralDashboardInfo);
    }
  };

  const handleClose = () => {
    onClose();
    dashboardForm.reset();
    ephemeralDashboardForm.reset();
  };

  return (
    <Dialog open={open} onClose={handleClose} aria-labelledby="confirm-dialog" fullWidth={true}>
      <Dialog.Header>
        {action} Dashboard{name && ': ' + name}
      </Dialog.Header>
      {mode == 'duplicate' && (
        <Dialog.Content sx={{ width: '100%' }}>
          <FormControlLabel
            control={
              <Switch
                checked={isTempCopyChecked}
                onChange={(event) => {
                  setTempCopyChecked(event.target.checked);
                }}
              />
            }
            label="Create as a temporary copy"
          />
        </Dialog.Content>
      )}
      {isTempCopyChecked ? (
        <FormProvider {...ephemeralDashboardForm}>
          <form onSubmit={ephemeralDashboardForm.handleSubmit(processEphemeralDashboardForm)}>
            <Dialog.Content sx={{ width: '100%' }}>
              <Stack gap={1}>
                {!hideProjectSelect && (
                  <Controller
                    name="projectName"
                    render={({ field, fieldState }) => (
                      <TextField
                        select
                        {...field}
                        required
                        id="project"
                        label="Project name"
                        type="text"
                        fullWidth
                        error={!!fieldState.error}
                        helperText={fieldState.error?.message}
                      >
                        {projectOptions.map((option) => {
                          return (
                            <MenuItem key={option} value={option}>
                              {option}
                            </MenuItem>
                          );
                        })}
                      </TextField>
                    )}
                  />
                )}
                <Controller
                  name="dashboardName"
                  render={({ field, fieldState }) => (
                    <TextField
                      {...field}
                      required
                      margin="dense"
                      id="name"
                      label="Dashboard Name"
                      type="text"
                      fullWidth
                      error={!!fieldState.error}
                      helperText={fieldState.error?.message}
                    />
                  )}
                />
                <Controller
                  name="ttl"
                  render={({ field, fieldState }) => (
                    <TextField
                      {...field}
                      required
                      margin="dense"
                      id="ttl"
                      label="Time to live (TTL)"
                      type="text"
                      fullWidth
                      error={!!fieldState.error}
                      helperText={
                        fieldState.error?.message ? fieldState.error.message : 'Duration string like 1w, 3d12h..'
                      }
                    />
                  )}
                />
              </Stack>
            </Dialog.Content>
            <Dialog.Actions>
              <Button variant="contained" disabled={!ephemeralDashboardForm.formState.isValid} type="submit">
                Add
              </Button>
              <Button variant="outlined" color="secondary" onClick={handleClose}>
                Cancel
              </Button>
            </Dialog.Actions>
          </form>
        </FormProvider>
      ) : (
        <FormProvider {...dashboardForm}>
          <form onSubmit={dashboardForm.handleSubmit(processDashboardForm)}>
            <Dialog.Content sx={{ width: '100%' }}>
              <Stack gap={1}>
                {!hideProjectSelect && (
                  <Controller
                    name="projectName"
                    render={({ field, fieldState }) => (
                      <TextField
                        select
                        {...field}
                        required
                        id="project"
                        label="Project name"
                        type="text"
                        fullWidth
                        error={!!fieldState.error}
                        helperText={fieldState.error?.message}
                      >
                        {projectOptions.map((option) => {
                          return (
                            <MenuItem key={option} value={option}>
                              {option}
                            </MenuItem>
                          );
                        })}
                      </TextField>
                    )}
                  />
                )}
                <Controller
                  name="dashboardName"
                  render={({ field, fieldState }) => (
                    <TextField
                      {...field}
                      required
                      margin="dense"
                      id="name"
                      label="Dashboard Name"
                      type="text"
                      fullWidth
                      error={!!fieldState.error}
                      helperText={fieldState.error?.message}
                    />
                  )}
                />
              </Stack>
            </Dialog.Content>
            <Dialog.Actions>
              <Button variant="contained" disabled={!dashboardForm.formState.isValid} type="submit">
                Add
              </Button>
              <Button variant="outlined" color="secondary" onClick={handleClose}>
                Cancel
              </Button>
            </Dialog.Actions>
          </form>
        </FormProvider>
      )}
    </Dialog>
  );
};
